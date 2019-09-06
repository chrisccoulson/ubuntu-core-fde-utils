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
	"reflect"

	"github.com/chrisccoulson/go-tpm2"
)

type ProvisionStatusAttributes int

const (
	ppiPath string = "/sys/class/tpm/tpm0/ppi/request"

	clearPPIRequest string = "5"

	maxTries        uint32 = 32
	recoveryTime    uint32 = 7200
	lockoutRecovery uint32 = 86400
)

const (
	AttrValidSRK ProvisionStatusAttributes = 1 << iota
	AttrDAParamsOK
	AttrOwnerClearDisabled
	AttrLockoutAuthSet
)

var (
	ErrClearRequiresPPI = errors.New("clearing requires the use of the Physical Presence Interface")

	srkTemplate = tpm2.Public{
		Type:    tpm2.AlgorithmRSA,
		NameAlg: tpm2.AlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin |
			tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.AlgorithmAES,
					KeyBits:   tpm2.SymKeyBitsU{Sym: 128},
					Mode:      tpm2.SymModeU{Sym: tpm2.AlgorithmCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
)

func ProvisionTPM(tpm tpm2.TPMContext, lockoutAuth []byte) error {
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return fmt.Errorf("cannot request permanent properties: %v", err)
	}

	p := tpm2.PermanentAttributes(props[0].Value)
	if p&tpm2.AttrLockoutAuthSet > 0 || p&tpm2.AttrDisableClear > 0 {
		return ErrClearRequiresPPI
	}

	if err := tpm.Clear(tpm2.HandleLockout, nil); err != nil {
		return fmt.Errorf("cannot clear the TPM: %v", err)
	}

	srkContext, _, _, _, _, _, err := tpm.CreatePrimary(tpm2.HandleOwner, nil, &srkTemplate, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("cannot create storage root key: %v", err)
	}
	defer tpm.FlushContext(srkContext)

	if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkHandle, nil); err != nil {
		return fmt.Errorf("cannot make storage root key persistent: %v", err)
	}

	if err := tpm.DictionaryAttackParameters(tpm2.HandleLockout, maxTries, recoveryTime, lockoutRecovery,
		nil); err != nil {
		return fmt.Errorf("cannot configure DA parameters: %v", err)
	}

	if err := tpm.ClearControl(tpm2.HandleLockout, true, nil); err != nil {
		return fmt.Errorf("cannot disable owner clear: %v", err)
	}

	sessionContext, err :=
		tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypeHMAC, &paramEncryptAlg, tpm2.AlgorithmSHA256,
			nil)
	if err != nil {
		return fmt.Errorf("cannot start session for command parameter encryption: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrCommandEncrypt}
	if err := tpm.HierarchyChangeAuth(tpm2.HandleLockout, tpm2.Auth(lockoutAuth), nil, &session); err != nil {
		return fmt.Errorf("cannot set the lockout hierarchy authorization value: %v", err)
	}

	return nil
}

func RequestTPMClearUsingPPI() error {
	f, err := os.OpenFile(ppiPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open request handle: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(clearPPIRequest); err != nil {
		return fmt.Errorf("cannot submit request: %v", err)
	}

	return nil
}

func checkForValidSRK(tpm tpm2.TPMContext) (bool, error) {
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		switch e := err.(type) {
		case tpm2.TPMHandleError:
			if e.Code == tpm2.ErrorHandle {
				return false, nil
			}
		}
		return false, fmt.Errorf("cannot create context for SRK: %v", err)
	}

	pub, _, qualifiedName, err := tpm.ReadPublic(srkContext)
	if err != nil {
		return false, fmt.Errorf("cannot read public part of SRK: %v", err)
	}

	if pub.Type != srkTemplate.Type {
		return false, nil
	}
	if pub.NameAlg != srkTemplate.NameAlg {
		return false, nil
	}
	if pub.Attrs != srkTemplate.Attrs {
		return false, nil
	}
	if !reflect.DeepEqual(pub.Params, srkTemplate.Params) {
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
	binary.BigEndian.PutUint16(alg, uint16(tpm2.AlgorithmSHA256))

	expectedQualifiedName := h.Sum(alg)
	if !bytes.Equal(expectedQualifiedName, qualifiedName) {
		return false, nil
	}

	return true, nil
}

func ProvisionStatus(tpm tpm2.TPMContext) (ProvisionStatusAttributes, error) {
	var out ProvisionStatusAttributes

	if valid, err := checkForValidSRK(tpm); err != nil {
		return 0, fmt.Errorf("cannot check for valid SRK: %v", err)
	} else if valid {
		out |= AttrValidSRK
	}

	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
	if err != nil {
		return 0, fmt.Errorf("cannot fetch DA parameters: %v", err)
	}
	if props[0].Value == maxTries && props[1].Value == recoveryTime && props[2].Value == lockoutRecovery {
		out |= AttrDAParamsOK
	}

	props, err = tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return 0, fmt.Errorf("cannot fetch permanent properties: %v", err)
	}
	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0 {
		out |= AttrOwnerClearDisabled
	}
	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrLockoutAuthSet > 0 {
		out |= AttrLockoutAuthSet
	}

	return out, nil
}
