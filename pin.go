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
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"golang.org/x/xerrors"
)

func pinNvIndexAuthPolicies(alg tpm2.HashAlgorithmId, keyName tpm2.Name) tpm2.DigestList {
	trial1, _ := tpm2.ComputeAuthPolicy(alg)
	trial1.PolicyCommandCode(tpm2.CommandNVWrite)
	trial1.PolicySigned(keyName, nil)

	trial2, _ := tpm2.ComputeAuthPolicy(alg)
	trial2.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	trial2.PolicyAuthValue()

	return tpm2.DigestList{trial1.GetDigest(), trial2.GetDigest()}
}

func createPinNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, ownerAuth []byte, hmacSession *tpm2.Session) (tpm2.ResourceContext, tpm2.Name, error) {
	// To prevent someone with knowledge of the owner authorization (which is empty unless someone has taken
	// ownership of the TPM) from resetting the PIN by just undefining and redifining a new NV index with the
	// same properties, require the NV index to be written to and only allow writes with a signed
	// authorization policy. This works because the name of the signing key is included in the authorization
	// policy digest for the NV index, and the authorization policy digest and written attribute is included
	// in the name of the NV index. The name of the NV index is included in the authorization policy for the
	// sealed key object. Without the private part of the signing key, it is impossible to create a new NV
	// index with the same name.

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create signing key for initializing NV index: %w", err)
	}

	keyPublic := createPublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of signing key for initializing NV index: %w", err)
	}

	nameAlg := tpm2.HashAlgorithmSHA256

	// The NV index requires 2 policies - one for writing in order to initialize, and one for changing the
	// auth value.
	authPolicies := pinNvIndexAuthPolicies(nameAlg, keyName)

	trial, _ := tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyOR(authPolicies)

	// Define the NV index
	nvPublic := tpm2.NVPublic{
		Index:      handle,
		NameAlg:    nameAlg,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeOrdinary),
		AuthPolicy: trial.GetDigest(),
		Size:       0}

	if err := tpm.NVDefineSpace(tpm2.HandleOwner, nil, &nvPublic, hmacSession.WithAuthValue(ownerAuth)); err != nil {
		return nil, nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	context, err := tpm.WrapHandle(handle)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot obtain context for new NV index: %w", err)
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm2.HandleOwner, context, hmacSession.WithAuthValue(ownerAuth))
	}()

	// The name associated with context is read back from the TPM with no integrity protection, so we don't know if it's correct yet.
	// We need to check that it's consistent with the NV index we created before adding it to an authorization policy.

	expectedName, err := nvPublic.Name()
	if err != nil {
		panic(fmt.Sprintf("cannot compute name of NV index: %v", err))
	}
	if !bytes.Equal(expectedName, context.Name()) {
		return nil, nil, errors.New("context for new NV index has unexpected name")
	}

	// Begin a session to initialize the index.
	policySessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nameAlg, nil)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot begin policy session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(policySessionContext)

	// Compute a digest for signing with our key
	signDigest := tpm2.HashAlgorithmSHA256
	h := signDigest.NewHash()
	h.Write(policySessionContext.(tpm2.SessionContext).NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0))

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, key, signDigest.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, _, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot load public part of key used to initialize NV index to the TPM: %w", err)
	}
	defer tpm.FlushContext(keyLoaded)

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: signDigest,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	// Execute the policy assertions
	if err := tpm.PolicyCommandCode(policySessionContext, tpm2.CommandNVWrite); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicyCommandCode assertion: %w", err)
	}
	if _, _, err := tpm.PolicySigned(keyLoaded, policySessionContext, true, nil, nil, 0, &signature); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicySigned assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(policySessionContext, authPolicies); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicyOR assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	if err := tpm.NVWrite(context, context, nil, 0, &tpm2.Session{Context: policySessionContext}); err != nil {
		return nil, nil, xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// Verify that the index now has the written attribute - if it doesn't for some reason, then it would be trivial for someone
	// to recreate the index with the same properties in order to remove the PIN. Pass a session in here for integrity protection.
	// This really should never actually fail, as the HMAC check success from the previous NVWrite is a guarantee that the command
	// executed on the TPM.
	nvPub, _, err := tpm.NVReadPublic(context, hmacSession.AddAttrs(tpm2.AttrAudit))
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot read NV index public area: %w", err)
	}
	if nvPub.Attrs&tpm2.AttrNVWritten == 0 {
		return nil, nil, errors.New("the NV index does not indicate that it has been initialized correctly")
	}

	succeeded = true
	return context, keyName, nil
}

func performPINChange(tpm *TPMConnection, index tpm2.ResourceContext, keyName tpm2.Name, oldAuth, newAuth string) error {
	hmacSession := tpm.HmacSession()

	nvPub, _, err := tpm.NVReadPublic(index, hmacSession.AddAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of NV index: %w", err)
	}

	policies := pinNvIndexAuthPolicies(nvPub.NameAlg, keyName)

	sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nvPub.NameAlg, nil)
	if err != nil {
		return xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(sessionContext)

	if err := tpm.PolicyCommandCode(sessionContext, tpm2.CommandNVChangeAuth); err != nil {
		return xerrors.Errorf("cannot execute PolicyCommandCode assertion: %w", err)
	}
	if err := tpm.PolicyAuthValue(sessionContext); err != nil {
		return xerrors.Errorf("cannot execute PolicyAuthValue assertion: %w", err)
	}
	if err := tpm.PolicyOR(sessionContext, policies); err != nil {
		return xerrors.Errorf("cannot execute PolicyOR assertion: %w", err)
	}

	session := tpm2.Session{
		Context:   sessionContext,
		AuthValue: []byte(oldAuth)}
	if err := tpm.NVChangeAuth(index, tpm2.Auth(newAuth), &session, hmacSession.AddAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return xerrors.Errorf("cannot change authorization value for NV index: %w", err)
	}

	return nil
}

func ChangePIN(tpm *TPMConnection, path string, oldAuth, newAuth string) error {
	// Open the key data file
	f, err := os.Open(path)
	if err != nil {
		return InvalidKeyFileError{fmt.Sprintf("cannot open key data file: %v", err)}
	}
	defer f.Close()

	data, err := readKeyData(f)
	if err != nil {
		return InvalidKeyFileError{err.Error()}
	}

	if err := data.validate(tpm.TPMContext, nil, tpm.HmacSession()); err != nil {
		switch e := err.(type) {
		case keyFileError:
			return InvalidKeyFileError{"integrity check failed: " + e.err.Error()}
		}
		return xerrors.Errorf("cannot integrity check key data file: %w", err)
	}

	pinIndex, _ := tpm.WrapHandle(data.StaticPolicyData.PinIndexHandle)
	if err := performPINChange(tpm, pinIndex, data.PinIndexKeyName, oldAuth, newAuth); err != nil {
		return err
	}

	if newAuth == "" {
		data.AskForPinHint = false
	} else {
		data.AskForPinHint = true
	}

	if err := data.writeToFileAtomic(path); err != nil {
		return fmt.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
