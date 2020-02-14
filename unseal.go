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

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func (k *SealedKeyObject) UnsealFromTPM(tpm *TPMConnection, pin string, lock bool) ([]byte, error) {
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
	keyContext, err := k.data.load(tpm)
	if err != nil {
		var kfErr keyFileError
		var ruErr tpm2.ResourceUnavailableError
		switch {
		case xerrors.As(err, &kfErr):
			// A keyFileError can be as a result of an improperly provisioned TPM - detect if the object at srkHandle is a valid primary
			// key with the correct attributes. If it's not, then it's definitely a provisioning error. If it is, then it could still
			// be a provisioning error because we don't know if the object was created with the same template that ProvisionTPM uses.
			// In that case, we'll just assume an invalid key file
			if srkContext, err := tpm.CreateResourceContextFromTPM(srkHandle); err != nil {
				if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
					return nil, ErrProvisioning
				}
				return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
			} else if ok, err := isObjectPrimaryKeyWithTemplate(tpm.TPMContext, tpm.OwnerHandleContext(), srkContext, &srkTemplate, tpm.HmacSession()); err != nil {
				return nil, xerrors.Errorf("cannot determine if object at 0x%08x is a primary key in the storage hierarchy: %w", srkHandle, err)
			} else if !ok {
				return nil, ErrProvisioning
			}
			// This is probably a broken key file, but it could still be a provisioning error because we don't know if the SRK object was
			// created with the same template that ProvisionTPM uses.
			return nil, InvalidKeyFileError{kfErr.err.Error()}
		case xerrors.As(err, &ruErr):
			return nil, ErrProvisioning
		}
		return nil, xerrors.Errorf("cannot load key data file: %w", err)
	}
	defer tpm.FlushContext(keyContext)

	// Begin and execute policy session
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, k.data.KeyPublic.NameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := executePolicySession(tpm, policySession, k.data.StaticPolicyData, k.data.DynamicPolicyData, pin); err != nil {
		var tpmsErr *tpm2.TPMSessionError
		if xerrors.As(err, &tpmsErr) && tpmsErr.Code() == tpm2.ErrorAuthFail && tpmsErr.Command() == tpm2.CommandPolicySecret {
			return nil, ErrPinFail
		}
		return nil, InvalidKeyFileError{fmt.Sprintf("encountered an error whilst executing the authorization policy assertions: %v", err)}
	}

	// Unseal
	key, err := tpm.Unseal(keyContext, policySession, hmacSession.IncludeAttrs(tpm2.AttrResponseEncrypt))
	if err != nil {
		if e, ok := err.(*tpm2.TPMSessionError); ok && e.Code() == tpm2.ErrorPolicyFail {
			return nil, InvalidKeyFileError{"the authorization policy check failed during unsealing"}
		}
		return nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	if lock {
		if err := lockAccessToSealedKeysUntilTPMReset(tpm.TPMContext, hmacSession); err != nil {
			return nil, fmt.Errorf("cannot lock sealed key object from further access: %v", err)
		}
	}

	return key, nil
}
