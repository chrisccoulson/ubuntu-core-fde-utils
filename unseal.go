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
	"errors"
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"
)

var (
	// ErrLockout is returned from UnsealKeyFromTPM when the TPM is in dictionary-attack lockout mode. Until
	// the TPM exits lockout mode, the key will need to be recovered via a mechanism that is independent of
	// the TPM (eg, a recovery key)
	ErrLockout = errors.New("the TPM is in DA lockout mode")

	// ErrPinFail is returned from UnsealKeyFromTPM when the provided PIN is incorrect.
	ErrPinFail = errors.New("the provided PIN is incorrect")

	// ErrPolicyRevoked is returned from UnsealKeyFromTPM when the authorization policy for the key has been
	// revoked. Unless there is another key object with an authorization policy that hasn't been revoked,
	// the key will need to be recovered via a mechanism that is indepdendent of the TPM (eg, a recovery key).
	// Once recovered, the key will need to be sealed to the TPM again with a new authorization policy.
	ErrPolicyRevoked = errors.New("the authorization policy has been revoked")
)

func UnsealKeyFromTPM(tpm *tpm2.TPMContext, buf io.Reader, pin string) ([]byte, error) {
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch properties from TPM: %v", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return nil, ErrLockout
	}

	// Load the key data
	var data keyData
	keyContext, pinContext, err := data.loadAndIntegrityCheck(buf, tpm, false)
	if err != nil {
		return nil, fmt.Errorf("cannot load key data: %v", err)
	}
	defer func() {
		tpm.FlushContext(keyContext)
		tpm.FlushContext(pinContext)
	}()

	// Begin and execute policy session
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	sessionContext, err :=
		tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypePolicy, &paramEncryptAlg,
			defaultHashAlgorithm, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot start policy session: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	if err := executePolicySession(tpm, sessionContext, pinContext, data.AuxData.PolicyData, pin); err != nil {
		switch err {
		case ErrPinFail:
			fallthrough
		case ErrPolicyRevoked:
			return nil, err
		default:
			return nil, fmt.Errorf("cannot complete execution of policy session: %v", err)
		}
	}

	// Unseal
	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrResponseEncrypt}
	key, err := tpm.Unseal(keyContext, &session)
	if err != nil {
		return nil, fmt.Errorf("cannot unseal key: %v", err)
	}

	return key, nil
}
