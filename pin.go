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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

func createPinNvIndex(tpm *TPMConnection, handle tpm2.Handle, ownerAuth []byte, hmacSession *tpm2.Session) (tpm2.ResourceContext, tpm2.DigestList, error) {
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

	keyPublic := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSAPSS,
					Details: tpm2.AsymSchemeU{
						Data: &tpm2.SigSchemeRSAPSS{HashAlg: tpm2.HashAlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: uint32(key.E)}},
		Unique: tpm2.PublicIDU{Data: tpm2.PublicKeyRSA(key.N.Bytes())}}

	keyName, err := keyPublic.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of signing key for initializing NV index: %w", err)
	}

	// The NV index requires 2 policies - one for writing in order to initialize, and one for changing the
	// auth value. Create the one for writing first
	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicySigned(keyName, nil)
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

	if err := tpm.NVDefineSpace(tpm2.HandleOwner, nil, &nvPublic, hmacSession.WithAuthValue(ownerAuth)); err != nil {
		return nil, nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	context, err := tpm.WrapHandle(handle)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot obtain context for new NV index: %w", err)
	}

	// The name associated with context is read back from the TPM with no integrity protection, so we don't know if it's correct yet.
	// We need to check that it's consistent with the NV index we created before adding it to an authorization policy.

	// Begin a session to initialize the index.
	ekContext, err := tpm.EkContext()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot obtain context for EK: %w", err)
	}
	policySessionContext, err := tpm.StartAuthSession(ekContext, nil, tpm2.SessionTypePolicy, nil, pinNvIndexNameAlgorithm, nil)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot begin policy session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(policySessionContext)

	// Compute a digest for signing with our key
	h := hashAlgToGoHash(tpm2.HashAlgorithmSHA256)
	h.Write(policySessionContext.(tpm2.SessionContext).NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0))

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, _, err := tpm.LoadExternal(nil, &keyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot load public part of key used to initialize NV index to the TPM: %w", err)
	}
	defer tpm.FlushContext(keyLoaded)

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: tpm2.HashAlgorithmSHA256,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	// Execute the policy assertions
	if _, _, err := tpm.PolicySigned(keyLoaded, policySessionContext, true, nil, nil, 0, &signature); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicySigned assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(policySessionContext, authPolicies); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicyOR assertion to initialize NV index: %w", err)
	}

	// Initialize the index. This command is integrity protected so it will fail if the name associated with context doesn't
	// correspond to the NV index. Success here confirms that the name associated with context corresponds to the actual NV index
	// that we created. Calling the ResourceContext.Name() method on it will return a value that can be safely used to compute an
	// authorization policy.
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

	return context, authPolicies, nil
}

func performPINChange(tpm *TPMConnection, handle tpm2.Handle, policies tpm2.DigestList, oldAuth, newAuth string) error {
	hmacSession, err := tpm.HmacSession()
	if err != nil {
		return err
	}

	pinIndexContext, err := tpm.WrapHandle(handle)
	if err != nil {
		return fmt.Errorf("cannot create context for PIN NV index: %v", err)
	}

	sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, pinNvIndexNameAlgorithm, nil)
	if err != nil {
		return fmt.Errorf("cannot start policy session: %v", err)
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
		AuthValue: []byte(oldAuth)}
	if err := tpm.NVChangeAuth(pinIndexContext, tpm2.Auth(newAuth), &session, hmacSession.AddAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return fmt.Errorf("cannot change authorization value for NV index: %v", err)
	}

	return nil
}

func ChangePIN(tpm *TPMConnection, path string, oldAuth, newAuth string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open key data file: %v", err)
	}
	defer f.Close()

	data, err := readKeyData(f)
	if err != nil {
		return fmt.Errorf("cannot load key data file: %v", err)
	}

	if err := performPINChange(tpm, data.PolicyData.PinIndexHandle, data.PinIndexPolicyORDigests, oldAuth, newAuth); err != nil {
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
