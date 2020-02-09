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
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
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

func createPinNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, hmacSession tpm2.SessionContext) (*tpm2.NVPublic, tpm2.Name, error) {
	// To prevent someone with knowledge of the owner authorization (which is empty unless someone has taken ownership of the TPM) from
	// resetting the PIN by just undefining and redifining a new NV index with the same properties, we need a way to prevent someone
	// from being able to create an index with the same name. To do this, we require the NV index to be written to and only allow writes
	// with a signed authorization policy. Once initialized, the signing key is discarded. This works because the name of the signing key
	// is included in the authorization policy digest for the NV index, and the authorization policy digest and written attribute is
	// included in the name of the NV index. Without the private part of the signing key, it is impossible to create a new NV index with
	// the same name, and so, if this NV index is undefined then it becomes impossible to satisfy the authorization policy for the sealed
	// key object.

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
	nvPublic := &tpm2.NVPublic{
		Index:      handle,
		NameAlg:    nameAlg,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeOrdinary),
		AuthPolicy: trial.GetDigest(),
		Size:       0}

	context, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, nvPublic, hmacSession)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), context, hmacSession)
	}()

	// Begin a session to initialize the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nameAlg)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot begin policy session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(policySession)

	// Compute a digest for signing with our key
	signDigest := tpm2.HashAlgorithmSHA256
	h := signDigest.NewHash()
	h.Write(policySession.NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0))

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, key, signDigest.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
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
	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVWrite); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicyCommandCode assertion: %w", err)
	}
	if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicySigned assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute PolicyOR assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	if err := tpm.NVWrite(context, context, nil, 0, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return nil, nil, xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// The index has a different name now that it has been written, so update the public area we return so that it can be used
	// to construct an authorization policy.
	nvPublic.Attrs |= tpm2.AttrNVWritten

	succeeded = true
	return nvPublic, keyName, nil
}

func performPINChange(tpm *TPMConnection, index tpm2.ResourceContext, keyName tpm2.Name, newAuth string) error {
	hmacSession := tpm.HmacSession()

	nvPub, _, err := tpm.NVReadPublic(index, hmacSession.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of NV index: %w", err)
	}

	policies := pinNvIndexAuthPolicies(nvPub.NameAlg, keyName)

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nvPub.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVChangeAuth); err != nil {
		return xerrors.Errorf("cannot execute PolicyCommandCode assertion: %w", err)
	}
	if err := tpm.PolicyAuthValue(policySession); err != nil {
		return xerrors.Errorf("cannot execute PolicyAuthValue assertion: %w", err)
	}
	if err := tpm.PolicyOR(policySession, policies); err != nil {
		return xerrors.Errorf("cannot execute PolicyOR assertion: %w", err)
	}

	if err := tpm.NVChangeAuth(index, tpm2.Auth(newAuth), policySession, hmacSession.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
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

	if err := data.validate(tpm, nil); err != nil {
		switch e := err.(type) {
		case keyFileError:
			return InvalidKeyFileError{"integrity check failed: " + e.err.Error()}
		}
		return xerrors.Errorf("cannot integrity check key data file: %w", err)
	}

	// FIXME: With the refactor-locking branch where we don't use read locking of the PIN NV index, have
	// validate() return the ResourceContext for this initialized from the validated public area, rather
	// than reading a public area from the TPM again.
	pinIndex, _ := tpm.CreateResourceContextFromTPM(data.StaticPolicyData.PinIndexHandle)
	pinIndex.SetAuthValue([]byte(oldAuth))
	if err := performPINChange(tpm, pinIndex, data.PinIndexKeyName, newAuth); err != nil {
		return err
	}

	if newAuth == "" {
		data.AuthModeHint = AuthModeNone
	} else {
		data.AuthModeHint = AuthModePIN
	}

	if err := data.writeToFileAtomic(path); err != nil {
		return fmt.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
