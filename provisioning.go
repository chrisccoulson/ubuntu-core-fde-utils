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
	"errors"
	"fmt"
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
	// AttrValidSRK indicates that the TPM contains a valid primary storage key with the expected properties at the
	// expected location.
	AttrValidSRK ProvisionStatusAttributes = 1 << iota

	// AttrValidEK indicates that the TPM contains a valid endorsement key at the expected location
	AttrValidEK

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

type ProvisionAuths struct {
	Owner       []byte
	Endorsement []byte
	Lockout     []byte
}

// ProvisionTPM prepares the TPM associated with the tpm parameter for full disk encryption. The mode parameter specifies the
// behaviour of this function.
//
// If mode is not ProvisionModeWithoutLockout, this function performs operations that require knowledge of the lockout hierarchy
// authorization value. If no authorization value is provided via the Lockout field of the auths parameter but the TPM indicates that
// the lockout hierarchy authorization value has previously been set, this will return a ErrRequiresLockoutAuth error. In this case,
// either the function should be called with the lockout hierarchy authorization (if it is known), or the TPM must be cleared via the
// physical presence interface by calling RequestTPMClearUsingPPI and performing a system restart. If the wrong lockout hierarchy
// authorization value is provided, then a AuthFailError error will be returned. If this happens, the TPM will have entered dictionary
// attack lockout mode for the lockout hierarchy. Further calls will result in a ErrLockout error being returned. The only way to
// recover from this is to either wait for the pre-programmed recovery time to expire, or to clear the TPM via the physical presence
// interface.
//
// If mode is ProvisionModeClear, this function will attempt to clear the TPM before provisioning it. If owner clear has been disabled
// (which will be the case if the TPM has previously been provisioned with this function), then ErrClearRequiresPPI will be returned.
// In this case, the TPM must be cleared via the physical presence interface by calling RequestTPMClearUsingPPI and performing a
// system restart.
//
// This function will create and persist an endorsement key, which requires knowledge of the authorization values for the storage
// and endorsement hierarchies. If called with mode set to ProvisionModeClear, or if called just after clearing the TPM via the
// physical presence interface, the authorization values for these hierarchies will be empty at the point that they are required. If
// called with any other mode and if the authorization values have previously been set, they will need to be provided via the Owner
// and Endorsement fields of the auths parameter. If the wrong value is provided for either authorization, then a AuthFailError
// error will be returned. If the correct authorization values are not known, then the only way to recover from this is to call the
// function with mode set to ProvisionModeClear. If there is an object already stored at the location used for the endorsement key
// then this function will evict it automatically from the TPM.
//
// This function will create and persist a storage root key, which requires knowledge of the authorization value for the storage
// hierarchy. If called with mode set to ProvisionModeClear, or if called just after clearing the TPM via the physical presence
// interface, the authorization value for the storage hierarchy will be empty at the point that it is required. If called with any
// other mode and if the authorization value for the storage hierarchy has previously been set, it will need to be provided via the
// Owner field of the auths parameter. If the wrong value is provided for the storage hierarchy authorization, then a AuthFailError
// error will be returned. If the correct authorization value is not known, then the only way to recover from this is to call the
// function with mode set to ProvisionModeClear. If there is an object already stored at the location used for the storage root key
// then this function will evict it automatically from the TPM.
//
// If mode is not ProvisionModeWithoutLockout, the authorization value for the lockout hierarchy will be set to newLockoutAuth
func ProvisionTPM(tpm *TPMConnection, mode ProvisionMode, newLockoutAuth []byte, auths *ProvisionAuths) error {
	status, err := ProvisionStatus(tpm)
	if err != nil {
		return xerrors.Errorf("cannot determine the current status: %w", err)
	}

	var ownerAuth []byte
	var endorsementAuth []byte
	var lockoutAuth []byte
	if auths != nil {
		ownerAuth = auths.Owner
		endorsementAuth = auths.Endorsement
		lockoutAuth = auths.Lockout
	}

	if mode != ProvisionModeWithoutLockout && status&AttrLockoutAuthSet > 0 && len(lockoutAuth) == 0 {
		// Don't needlessly trip the lockout hierarchy DA protection, as you only get one attempt
		// at the lockout hierarchy authorization
		return ErrRequiresLockoutAuth
	}

	// Create an initial session for HMAC authorizations
	sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, defaultHashAlgorithm, nil)
	if err != nil {
		return xerrors.Errorf("cannot start session: %w", err)
	}
	defer tpm.FlushContext(sessionContext)

	session := &tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrContinueSession}

	if mode == ProvisionModeClear {
		if status&AttrOwnerClearDisabled > 0 {
			return ErrClearRequiresPPI
		}

		if err := tpm.Clear(tpm2.HandleLockout, session.WithAuthValue(lockoutAuth)); err != nil {
			switch {
			case isAuthFailError(err):
				return AuthFailError{tpm2.HandleLockout}
			case isLockoutError(err):
				return ErrLockout
			}
			return xerrors.Errorf("cannot clear the TPM: %w", err)
		}

		// These values are all clear now
		lockoutAuth = nil
		ownerAuth = nil
		endorsementAuth = nil
		status = 0
	}

	// Provision an endorsement key
	ekContext, err := tpm.WrapHandle(ekHandle)
	if err == nil {
		if _, err := tpm.EvictControl(tpm2.HandleOwner, ekContext, ekHandle, session.WithAuthValue(ownerAuth)); err != nil {
			if isAuthFailError(err) {
				return AuthFailError{tpm2.HandleOwner}
			}
			return xerrors.Errorf("cannot evict existing object at handle required by endorsement key: %w", err)
		}
	} else if _, notFound := err.(tpm2.ResourceUnavailableError); !notFound {
		return xerrors.Errorf("cannot create context for object at handle required by endorsement key: %w", err)
	}

	ekContext, _, _, _, _, _, err = tpm.CreatePrimary(tpm2.HandleEndorsement, nil, &ekTemplate, nil, nil,
		session.WithAuthValue(endorsementAuth))
	if err != nil {
		if isAuthFailError(err) {
			return AuthFailError{tpm2.HandleEndorsement}
		}
		return xerrors.Errorf("cannot create endorsement key: %w", err)
	}
	defer tpm.FlushContext(ekContext)

	if _, err := tpm.EvictControl(tpm2.HandleOwner, ekContext, ekHandle, session.WithAuthValue(ownerAuth)); err != nil {
		if isAuthFailError(err) {
			return AuthFailError{tpm2.HandleOwner}
		}
		return xerrors.Errorf("cannot make endorsement key persistent: %w", err)
	}

	// Close the existing session and create a new session that's salted with a value protected with the newly provisioned EK.
	// This will have a symmetric algorithm for parameter encryption during HierarchyChangeAuth.
	tpm.FlushContext(sessionContext)
	if err := tpm.init(nil); err != nil {
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return TPMVerificationError{fmt.Sprintf("cannot reinitialize TPM connection after provisioning endorsement key: %v", err)}
		}
		return xerrors.Errorf("cannot reinitialize TPM connection after provisioning endorsement key: %w", err)
	}
	session = tpm.HmacSession()

	// Provision a storage root key
	if status&AttrValidSRK == 0 {
		srkContext, err := tpm.WrapHandle(srkHandle)
		if err == nil {
			if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkHandle, session.WithAuthValue(ownerAuth)); err != nil {
				if isAuthFailError(err) {
					return AuthFailError{tpm2.HandleOwner}
				}
				return xerrors.Errorf("cannot evict existing object at handle required by storage root key: %w", err)
			}
		} else if _, notFound := err.(tpm2.ResourceUnavailableError); !notFound {
			return xerrors.Errorf("cannot create context for object at handle required by storage root key: %w", err)
		}

		srkContext, _, _, _, _, _, err = tpm.CreatePrimary(tpm2.HandleOwner, nil, &srkTemplate, nil, nil, session.WithAuthValue(ownerAuth))
		if err != nil {
			if isAuthFailError(err) {
				return AuthFailError{tpm2.HandleOwner}
			}
			return xerrors.Errorf("cannot create storage root key: %w", err)
		}
		defer tpm.FlushContext(srkContext)

		if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkHandle, session.WithAuthValue(ownerAuth)); err != nil {
			// Owner auth failure would have been caught by CreatePrimary
			return xerrors.Errorf("cannot make storage root key persistent: %w", err)
		}
	}

	if mode == ProvisionModeWithoutLockout {
		return nil
	}

	// Perform actions that require the lockout hierarchy authorization.

	// Set the DA parameters.
	if err := tpm.DictionaryAttackParameters(tpm2.HandleLockout, maxTries, recoveryTime, lockoutRecovery,
		session.WithAuthValue(lockoutAuth)); err != nil {
		switch {
		case isAuthFailError(err):
			return AuthFailError{tpm2.HandleLockout}
		case isLockoutError(err):
			return ErrLockout
		}
		return xerrors.Errorf("cannot configure dictionary attack parameters: %w", err)
	}

	// Disable owner clear
	if err := tpm.ClearControl(tpm2.HandleLockout, true, session.WithAuthValue(lockoutAuth)); err != nil {
		// Lockout auth failure or lockout mode would have been caught by DictionaryAttackParameters
		return xerrors.Errorf("cannot disable owner clear: %w", err)
	}

	// Set the lockout hierarchy authorization.
	if err := tpm.HierarchyChangeAuth(tpm2.HandleLockout, tpm2.Auth(newLockoutAuth),
		session.WithAuthValue(lockoutAuth).AddAttrs(tpm2.AttrCommandEncrypt)); err != nil {
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

// isObjectPrimaryKeyWithTemplate checks whether the object associated with context is primary key in the specified hierarchy with
// the specified template.
//
// This isn't completely accurate as it does not know if the unique field of the specified template was used to create the object,
// so it should be used with caution. This function returning true is no guarantee that recreating the object with the specified
// template would create the same object.
func isObjectPrimaryKeyWithTemplate(tpm *tpm2.TPMContext, hierarchy tpm2.Handle, context tpm2.ResourceContext,
	template *tpm2.Public, session *tpm2.Session) (bool, error) {
	var auditSession *tpm2.Session
	if session != nil {
		auditSession = session.AddAttrs(tpm2.AttrAudit)
	}

	pub, name, qualifiedName, err := tpm.ReadPublic(context, auditSession)
	if err != nil {
		return false, xerrors.Errorf("cannot read public area of object: %w", err)
	}
	if !bytes.Equal(name, context.Name()) {
		return false, errors.New("public area does not match ResourceContext")
	}

	pub.Unique = template.Unique

	pubBytes, _ := tpm2.MarshalToBytes(pub)
	templateBytes, _ := tpm2.MarshalToBytes(template)
	if !bytes.Equal(pubBytes, templateBytes) {
		if template.Type == tpm2.ObjectTypeRSA && template.Params.RSADetail().Exponent == 0 {
			var templateCopy *tpm2.Public
			tpm2.UnmarshalFromBytes(templateBytes, &templateCopy)
			templateCopy.Params.RSADetail().Exponent = 65537
			templateBytes, _ = tpm2.MarshalToBytes(templateCopy)
			if !bytes.Equal(pubBytes, templateBytes) {
				return false, nil
			}
		} else {
			return false, nil
		}
	}

	parent, _ := tpm.WrapHandle(hierarchy)

	// Determine if this is a primary key by validating its qualified name. From the spec, the qualified name
	// of key B (QNb) which is a child of key A is QNb = Hb(QNa || NAMEb). Key A in this case should be
	// the storage primary seed, which has a qualified name matching its name (and the name is the handle
	// for the storage hierarchy)
	h := sha256.New()
	h.Write(parent.Name())
	h.Write(context.Name())

	alg := make([]byte, 2)
	binary.BigEndian.PutUint16(alg, uint16(tpm2.HashAlgorithmSHA256))

	expectedQualifiedName := h.Sum(alg)
	if !bytes.Equal(expectedQualifiedName, qualifiedName) {
		return false, nil
	}

	return true, nil
}

func hasValidSRK(tpm *tpm2.TPMContext, session *tpm2.Session) (bool, error) {
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
			return false, nil
		}
		return false, xerrors.Errorf("cannot obtain context for SRK: %w", err)
	}

	if ok, err := isObjectPrimaryKeyWithTemplate(tpm, tpm2.HandleOwner, srkContext, &srkTemplate, session); err != nil {
		return false, xerrors.Errorf("cannot determine if object at SRK handle is a primary key in the storage hierarchy: %w", err)
	} else if !ok {
		return false, nil
	}

	return true, nil
}

func ProvisionStatus(tpm *TPMConnection) (ProvisionStatusAttributes, error) {
	var out ProvisionStatusAttributes

	if rc, err := tpm.EkContext(); err == nil && rc.Handle() != tpm2.HandleUnassigned {
		out |= AttrValidEK
	}

	if ok, err := hasValidSRK(tpm.TPMContext, tpm.HmacSession()); err != nil {
		return 0, err
	} else if ok {
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
