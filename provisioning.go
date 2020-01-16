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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

// ProvisionStatusAttributes correspond to the state of the TPM with regards to provisioning for full disk
// encryption.
type ProvisionStatusAttributes int

// ProvisionMode is used to control the behaviour of ProvisionTPM.
type ProvisionMode int

const (
	ppiPath string = "/sys/class/tpm/tpm0/ppi/request"

	clearPPIRequest string = "5"

	maxTries        uint32 = 32
	recoveryTime    uint32 = 7200
	lockoutRecovery uint32 = 86400
)

const (
	// AttrValidSRK indicates that the TPM contains a valid primary key with the expected properties at the
	// expected location.
	AttrValidSRK ProvisionStatusAttributes = 1 << iota

	AttrDAParamsOK         // The dictionary attack lockout parameters are configured correctly.
	AttrOwnerClearDisabled // The ability to clear the TPM with owner authorization is disabled.

	// AttrLockoutAuthSet indicates that the lockout hierarchy has an authorization value defined. This
	// doesn't necessarily mean that the authorization value is the same one that was originally provided
	// to TPM - it could have been changed outside of our control.
	AttrLockoutAuthSet
)

const (
	// ProvisionModeClear specifies that the TPM should be fully provisioned after clearing it.
	ProvisionModeClear ProvisionMode = iota

	// ProvisionModeWithoutLockout specifies that the TPM should be refreshed without performing
	// operations that require knowledge of the lockout hierarchy authorization value.
	ProvisionModeWithoutLockout

	// ProvisionModeFull specifies that the TPM should be fully provisioned without clearing it.
	ProvisionModeFull
)

var (
	srkTemplate = tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted |
			tpm2.AttrDecrypt,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.SymKeyBitsU{Data: uint16(128)},
					Mode:      tpm2.SymModeU{Data: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
)

// ProvisionTPM prepares the TPM associated with the tpm parameter for full disk encryption. The mode parameter
// specifies the behaviour of this function.
//
// If mode is not ProvisionModeWithoutLockout, this function performs operations that require knowledge of the
// lockout hierarchy authorization value. If no authorization value is provided via lockoutAuth but the TPM
// indicates that the lockout hierarchy authorization value has previously been set, this will return a
// ErrRequiresLockoutAuth error. In this case, either the function should be called with the lockout hierarchy
// authorization (if it is known), or the TPM must be cleared via the physical presence interface by calling
// RequestTPMClearUsingPPI and performing a system restart. If the wrong lockout hierarchy authorization value is
// provided, then a ErrLockoutAuthFail error will be returned. If this happens, the TPM will have entered
// dictionary attack lockout mode for the lockout hierarchy. Further calls will result in a ErrInLockout error
// being returned. The only way to recover from this is to either wait for the pre-programmed recovery time to
// expire, or to clear the TPM via the physical presence interface.
//
// If mode is ProvisionModeClear, this function will attempt to clear the TPM before provisioning it. If owner
// clear has been disabled (which will be the case if the TPM has previously been provisioned with this function),
// then ErrClearRequiresPPI will be returned. In this case, the TPM must be cleared via the physical presence
// interface by calling RequestTPMClearUsingPPI and performing a system restart.
//
// This function will create and persist a storage root key if required, which requires knowledge of the
// authorization value for the storage hierarchy. If called with mode set to ProvisionModeClear, or if called
// just after clearing the TPM via the physical presence interface, the authorization value for the storage
// hierarchy will be empty at the point that it is required. If called with any other mode and if the
// authorization value for the storage hierarchy has previously been set, it will need to be provided via the
// ownerAuth parameter. If the wrong value is provided for the storage hierarchy authorization, then a
// ErrOwnerAuthFail error will be returned. If the correct authorization value is not known, then the only way
// to recover from this is to call the function with mode set to ProvisionModeClear. If there is an object already
// stored at the location used for the storage root key, and that object is not a primary key or doesn't have the
// expected public template, then this function will evict it automatically from the TPM.
//
// If mode is not ProvisionModeWithoutLockout, the authorization value for the lockout hierarchy will be set to
// newLockoutAuth
func ProvisionTPM(tpm *tpm2.TPMContext, mode ProvisionMode, newLockoutAuth, ownerAuth, lockoutAuth []byte) error {
	status, err := ProvisionStatus(tpm)
	if err != nil {
		return xerrors.Errorf("cannot determine the current status: %w", err)
	}

	if mode != ProvisionModeWithoutLockout && status&AttrLockoutAuthSet > 0 && len(lockoutAuth) == 0 {
		// Don't needlessly trip the lockout hierarchy DA protection, as you only get one attempt
		// at the lockout hierarchy authorization
		return ErrRequiresLockoutAuth
	}

	if mode == ProvisionModeClear {
		if status&AttrOwnerClearDisabled > 0 {
			return ErrClearRequiresPPI
		}

		if err := tpm.Clear(tpm2.HandleLockout, lockoutAuth); err != nil {
			switch {
			case isAuthFailError(err):
				return ErrLockoutAuthFail
			case isLockoutError(err):
				return ErrInLockout
			}
			return xerrors.Errorf("cannot clear the TPM: %w", err)
		}

		lockoutAuth = nil
		ownerAuth = nil
		status = 0
	}

	if status&AttrValidSRK == 0 {
		srkContext, err := tpm.WrapHandle(srkHandle)
		if err == nil {
			if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkHandle, ownerAuth); err != nil {
				if isAuthFailError(err) {
					return ErrOwnerAuthFail
				}
				return xerrors.Errorf("cannot evict existing object at handle required by storage root key: %w", err)
			}
		} else if _, notFound := err.(tpm2.ResourceUnavailableError); !notFound {
			return xerrors.Errorf("cannot create context for object at handle required by storage root key: %w", err)
		}

		srkContext, _, _, _, _, _, err = tpm.CreatePrimary(tpm2.HandleOwner, nil, &srkTemplate, nil, nil, ownerAuth)
		if err != nil {
			if isAuthFailError(err) {
				return ErrOwnerAuthFail
			}
			return xerrors.Errorf("cannot create storage root key: %w", err)
		}
		defer tpm.FlushContext(srkContext)

		if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkHandle, ownerAuth); err != nil {
			// Owner auth failure would have been caught by CreatePrimary
			return xerrors.Errorf("cannot make storage root key persistent: %w", err)
		}
	}

	if mode == ProvisionModeWithoutLockout {
		return nil
	}

	if err := tpm.DictionaryAttackParameters(tpm2.HandleLockout, maxTries, recoveryTime, lockoutRecovery, lockoutAuth); err != nil {
		switch {
		case isAuthFailError(err):
			return ErrLockoutAuthFail
		case isLockoutError(err):
			return ErrInLockout
		}
		return xerrors.Errorf("cannot configure dictionary attack parameters: %w", err)
	}

	if err := tpm.ClearControl(tpm2.HandleLockout, true, lockoutAuth); err != nil {
		// Lockout auth failure or lockout mode would have been caught by DictionaryAttackParameters
		return xerrors.Errorf("cannot disable owner clear: %w", err)
	}

	// This was either created by ProvisionStatus or by TPMContext.EvictControl if we needed to create a new one, so this can never fail
	srkContext, _ := tpm.WrapHandle(srkHandle)
	lockoutContext, _ := tpm.WrapHandle(tpm2.HandleLockout)
	sessionContext, err :=
		tpm.StartAuthSession(srkContext, lockoutContext, tpm2.SessionTypeHMAC, &paramEncryptAlg, defaultSessionHashAlgorithm, lockoutAuth)
	if err != nil {
		return xerrors.Errorf("cannot start session for command parameter encryption: %w", err)
	}
	defer tpm.FlushContext(sessionContext)

	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrCommandEncrypt, AuthValue: lockoutAuth}
	if err := tpm.HierarchyChangeAuth(tpm2.HandleLockout, tpm2.Auth(newLockoutAuth), lockoutAuth, &session); err != nil {
		return xerrors.Errorf("cannot set the lockout hierarchy authorization value: %w", err)
	}

	return nil
}

func RequestTPMClearUsingPPI() error {
	f, err := os.OpenFile(ppiPath, os.O_WRONLY, 0)
	if err != nil {
		return xerrors.Errorf("cannot open request handle: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(clearPPIRequest); err != nil {
		return xerrors.Errorf("cannot submit request: %w", err)
	}

	return nil
}

func checkForValidSRK(tpm *tpm2.TPMContext) (bool, error) {
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		if _, notFound := err.(tpm2.ResourceUnavailableError); notFound {
			return false, nil
		}
		return false, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	pub, _, qualifiedName, err := tpm.ReadPublic(srkContext)
	if err != nil {
		return false, xerrors.Errorf("cannot read public part of SRK: %w", err)
	}

	pub.Unique = tpm2.PublicIDU{}

	srkPubBytes, _ := tpm2.MarshalToBytes(pub)
	srkTemplateBytes, _ := tpm2.MarshalToBytes(srkTemplate)
	if !bytes.Equal(srkPubBytes, srkTemplateBytes) {
		return false, nil
	}

	owner, _ := tpm.WrapHandle(tpm2.HandleOwner)

	// Determine if this is a primary key by validating its qualified name. From the spec, the qualified name
	// of key B (QNb) which is a child of key A is QNb = Hb(QNa || NAMEb). Key A in this case should be
	// the storage primary seed, which has a qualified name matching its name (and the name is the handle
	// for the storage hierarchy)
	h := sha256.New()
	h.Write(owner.Name())
	h.Write(srkContext.Name())

	alg := make([]byte, 2)
	binary.BigEndian.PutUint16(alg, uint16(srkTemplate.NameAlg))

	expectedQualifiedName := h.Sum(alg)
	if !bytes.Equal(expectedQualifiedName, qualifiedName) {
		return false, nil
	}

	return true, nil
}

func ProvisionStatus(tpm *tpm2.TPMContext) (ProvisionStatusAttributes, error) {
	var out ProvisionStatusAttributes

	if valid, err := checkForValidSRK(tpm); err != nil {
		return 0, xerrors.Errorf("cannot check for valid SRK: %w", err)
	} else if valid {
		out |= AttrValidSRK
	}

	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
	if err != nil {
		return 0, xerrors.Errorf("cannot fetch DA parameters: %w", err)
	}
	if props[0].Value <= maxTries && props[1].Value >= recoveryTime && props[2].Value >= lockoutRecovery {
		out |= AttrDAParamsOK
	}

	props, err = tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return 0, xerrors.Errorf("cannot fetch permanent properties: %w", err)
	}
	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0 {
		out |= AttrOwnerClearDisabled
	}
	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrLockoutAuthSet > 0 {
		out |= AttrLockoutAuthSet
	}

	return out, nil
}
