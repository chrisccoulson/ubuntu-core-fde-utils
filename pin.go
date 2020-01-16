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
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"golang.org/x/xerrors"
)

const (
	pinNvIndexNameAlgorithm tpm2.HashAlgorithmId = tpm2.HashAlgorithmSHA256
)

func createPinNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, ownerAuth interface{}) (tpm2.ResourceContext, tpm2.DigestList, error) {
	// To prevent someone with knowledge of the owner authorization (which is empty unless someone has taken
	// ownership of the TPM) from resetting the PIN by just undefining and redifining a new NV index with the
	// same properties, require the NV index to be written to and only allow writes with a signed
	// authorization policy. This works because the name of the signing key is included in the authorization
	// policy digest for the NV index, and the authorization policy digest and written attribute is included
	// in the name of the NV index. The name of the NV index is included in the authorization policy for the
	// sealed key object. Without the private part of the signing key, it is impossible to create a new NV
	// index with the same name.

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	// Create and load a signing key
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSAPSS,
					Details: tpm2.AsymSchemeU{
						Data: &tpm2.SigSchemeRSAPSS{HashAlg: tpm2.HashAlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}}
	priv, pub, _, _, _, err := tpm.Create(srkContext, nil, &template, nil, nil, nil)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create signing key for initializing NV index: %w", err)
	}
	key, _, err := tpm.Load(srkContext, priv, pub, nil)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot load signing key to initialize NV index: %2", err)
	}
	defer tpm.FlushContext(key)

	// The NV index requires 2 policies - one for writing in order to initialize, and one for changing the
	// auth value. Create the one for writing first
	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicySigned(key, nil)
	authPolicy1 := trial.GetDigest()

	// The second policy is for changing the auth value which requires the admin role, so we use
	// PolicyCommandCode for this
	trial, _ = tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	trial.PolicyAuthValue()
	authPolicy2 := trial.GetDigest()

	authPolicies := tpm2.DigestList{authPolicy1, authPolicy2}

	trial, _ = tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyOR(authPolicies)
	authPolicy := trial.GetDigest()

	// Define the NV index
	nvPublic := tpm2.NVPublic{
		Index:      handle,
		NameAlg:    pinNvIndexNameAlgorithm,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeOrdinary),
		AuthPolicy: authPolicy,
		Size:       0}

	if err := tpm.NVDefineSpace(tpm2.HandleOwner, nil, &nvPublic, ownerAuth); err != nil {
		return nil, nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	context, err := tpm.WrapHandle(handle)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot obtain context for new NV index: %w", err)
	}

	// Begin a session to initialize the index
	sessionContext, err := tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypePolicy, nil, pinNvIndexNameAlgorithm, nil)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot begin authorization session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(sessionContext)

	// Compute a digest for signing with our key
	h := hashAlgToGoHash(tpm2.HashAlgorithmSHA256)
	h.Write(sessionContext.(tpm2.SessionContext).NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0))

	// Sign the digest
	signature, err := tpm.Sign(key, h.Sum(nil), nil, nil, nil)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot produce signed authorization to initialize NV index: %w", err)
	}

	// Execute the policy assertions
	if _, _, err := tpm.PolicySigned(key, sessionContext, true, nil, nil, 0, signature); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicySigned assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(sessionContext, authPolicies); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicyOR assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	session := tpm2.Session{Context: sessionContext}
	if err := tpm.NVWrite(context, context, nil, 0, &session); err != nil {
		return nil, nil, xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// Verify that the index now has the written attribute - if it doesn't for some reason, then it would
	// be trivial for someone to recreate the index with the same properties in order to remove the PIN
	nvPub, _, err := tpm.NVReadPublic(context)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot read NV index public area: %w", err)
	}
	if nvPub.Attrs&tpm2.AttrNVWritten == 0 {
		return nil, nil, errors.New("the NV index does not indicate that it has been initialized correctly")
	}

	return context, authPolicies, nil
}

func performPINChange(tpm *tpm2.TPMContext, handle tpm2.Handle, policies tpm2.DigestList, oldAuth,
	newAuth string) error {
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return fmt.Errorf("cannot create context for SRK handle: %v", err)
	}
	pinIndexContext, err := tpm.WrapHandle(handle)
	if err != nil {
		return fmt.Errorf("cannot create context for PIN NV index: %v", err)
	}

	sessionContext, err := tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypePolicy, &paramEncryptAlg, pinNvIndexNameAlgorithm, nil)
	if err != nil {
		return fmt.Errorf("cannot start auth session: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	if err := tpm.PolicyCommandCode(sessionContext, tpm2.CommandNVChangeAuth); err != nil {
		return fmt.Errorf("cannot execute PolicyCommandCode assertion: %v", err)
	}
	if err := tpm.PolicyAuthValue(sessionContext); err != nil {
		return fmt.Errorf("cannot execute PolicyAuthValue assertion: %v", err)
	}
	if err := tpm.PolicyOR(sessionContext, policies); err != nil {
		return fmt.Errorf("cannot execute PolicyOR assertion: %v", err)
	}

	session := tpm2.Session{
		Context:   sessionContext,
		Attrs:     tpm2.AttrCommandEncrypt,
		AuthValue: []byte(oldAuth)}
	if err := tpm.NVChangeAuth(pinIndexContext, tpm2.Auth(newAuth), &session); err != nil {
		return fmt.Errorf("cannot change authorization value for NV index: %v", err)
	}

	return nil
}

func ChangePIN(tpm *tpm2.TPMContext, path string, oldAuth, newAuth string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open key data file: %v", err)
	}
	defer f.Close()

	var data keyData
	_, err = data.loadAndIntegrityCheck(f, tpm, true)
	if err != nil {
		return fmt.Errorf("cannot load DEK file: %v", err)
	}

	if err := performPINChange(tpm, data.AuxData.PolicyData.PinIndexHandle,
		data.AuxData.PinIndexPolicyORDigests, oldAuth, newAuth); err != nil {
		return err
	}

	if newAuth == "" {
		data.AskForPinHint = false
	} else {
		data.AskForPinHint = true
	}

	if err := data.writeToFile(path); err != nil {
		return fmt.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
