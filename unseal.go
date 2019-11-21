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
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func UnsealKeyFromTPM(tpm *TPMConnection, buf io.Reader, pin string) ([]byte, error) {
	// Check if the TPM is in lockout mode
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return nil, xerrors.Errorf("cannot fetch properties from TPM: %w", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return nil, ErrLockout
	}

	// Use the HMAC session created when the connection was opened for parameter encryption rather than creating a new one.
	hmacSession := tpm.HmacSession()

	// Load the key data
	keyContext, data, err := loadKeyData(tpm.TPMContext, buf)
	if err != nil {
		var kfErr keyFileError
		if xerrors.As(err, &kfErr) {
			// A keyFileError can be as a result of an improperly provisioned TPM - detect if
			// the object at srkHandle is a valid primary key with the correct template. If it's
			// not, then return a provisioning error.
			if ok, err := hasValidSRK(tpm.TPMContext, hmacSession); err == nil && !ok {
				return nil, ErrProvisioning
			}
			return nil, InvalidKeyFileError{kfErr.err.Error()}
		}
		var ruErr tpm2.ResourceUnavailableError
		if xerrors.As(err, &ruErr) {
			return nil, ErrProvisioning
		}
		return nil, xerrors.Errorf("cannot load key data file: %w", err)
	}
	defer tpm.FlushContext(keyContext)

	// Begin and execute policy session
	sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, defaultHashAlgorithm, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(sessionContext)

	if err := executePolicySession(tpm, sessionContext, data.PolicyData, pin); err != nil {
		var tpmsErr *tpm2.TPMSessionError
		if xerrors.As(err, &tpmsErr) && tpmsErr.Code() == tpm2.ErrorAuthFail && tpmsErr.Command() == tpm2.CommandPolicySecret {
			return nil, ErrPinFail
		}
		return nil, InvalidKeyFileError{fmt.Sprintf("encountered an error whilst executing the authorization policy assertions: %v", err)}
	}

	// Unseal
	key, err := tpm.Unseal(keyContext, &tpm2.Session{Context: sessionContext}, hmacSession.AddAttrs(tpm2.AttrResponseEncrypt))
	if err != nil {
		if e, ok := err.(*tpm2.TPMSessionError); ok && e.Code() == tpm2.ErrorPolicyFail {
			return nil, InvalidKeyFileError{"the authorization policy check failed during unsealing"}
		}
		return nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	return key, nil
}
