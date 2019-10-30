// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package fdeutil

import (
	"io"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func UnsealKeyFromTPM(tpm *tpm2.TPMContext, buf io.Reader, pin string) ([]byte, error) {
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return nil, xerrors.Errorf("cannot fetch properties from TPM: %w", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return nil, ErrLockout
	}

	// Load the key data
	var data keyData
	keyContext, err := data.loadAndIntegrityCheck(buf, tpm, false)
	if err != nil {
		var kfErr keyFileError
		var ruErr tpm2.ResourceUnavailableError
		switch {
		case xerrors.As(err, &kfErr):
			// A keyFileError can be as a result of an improperly provisioned TPM - detect if
			// the object at srkHandle is a valid primary key with the correct template. If it's
			// not, then return a provisioning error.
			if status, err := ProvisionStatus(tpm); err == nil && status&AttrValidSRK == 0 {
				return nil, ErrProvisioning
			}
			return nil, InvalidKeyFileError{kfErr.msg}
		case xerrors.As(err, &ruErr):
			if ruErr.Handle == srkHandle {
				// There's no object at srkHandle
				return nil, ErrProvisioning
			}
		}
		return nil, xerrors.Errorf("cannot load key data file: %w", err)
	}
	defer tpm.FlushContext(keyContext)

	// Begin and execute policy session

	// This can't fail, as keyData.loadAndIntegrityCheck already created it
	srkContext, _ := tpm.WrapHandle(srkHandle)

	sessionContext, err := tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypePolicy, &paramEncryptAlg, defaultHashAlgorithm, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(sessionContext)

	if err := executePolicySession(tpm, sessionContext, data.AuxData.PolicyData, pin); err != nil {
		var tpmErr *tpm2.TPMError
		var tpmsErr *tpm2.TPMSessionError
		switch {
		case xerrors.As(err, &tpmsErr):
			if tpmsErr.Code() == tpm2.ErrorAuthFail && tpmsErr.Command() == tpm2.CommandPolicySecret {
				return nil, ErrPinFail
			}
		case xerrors.As(err, &tpmErr):
			if tpmErr.Code == tpm2.ErrorPolicy && tpmErr.Command == tpm2.CommandPolicyNV {
				return nil, ErrPolicyRevoked
			}
		}
		return nil, xerrors.Errorf("cannot complete execution of policy session: %w", err)
	}

	// Unseal
	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrResponseEncrypt}
	key, err := tpm.Unseal(keyContext, &session)
	if err != nil {
		if e, ok := err.(*tpm2.TPMSessionError); ok && e.Code() == tpm2.ErrorPolicyFail {
			return nil, ErrPolicyFail
		}
		return nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	return key, nil
}
