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

func createPinNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, updateKey *rsa.PublicKey, hmacSession tpm2.SessionContext) (*tpm2.NVPublic, tpm2.DigestList, error) {
	// To prevent someone with knowledge of the owner authorization (which is empty unless someone has taken ownership of the TPM) from
	// resetting the PIN by just undefining and redifining a new NV index with the same properties, we need a way to prevent someone
	// from being able to create an index with the same name. To do this, we require the NV index to be written to and only allow writes
	// with a signed authorization policy. Once initialized, the signing key is discarded. This works because the name of the signing key
	// is included in the authorization policy digest for the NV index, and the authorization policy digest and written attribute is
	// included in the name of the NV index. Without the private part of the signing key, it is impossible to create a new NV index with
	// the same name, and so, if this NV index is undefined then it becomes impossible to satisfy the authorization policy for the sealed
	// key object.
	//
	// The PIN index also doubles as a counter for revoking dynamic authorization policies. As a consequence the authorization policy
	// allows the index to be incremented with the dynamic authorization policy signing key, but only if the index has already been
	// initialized.

	updateKeyPublic := createPublicAreaForRSASigningKey(updateKey)
	updateKeyName, err := updateKeyPublic.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of signing key for updating NV index: %w", err)
	}

	initKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create signing key for initializing NV index: %w", err)
	}

	initKeyPublic := createPublicAreaForRSASigningKey(&initKey.PublicKey)
	initKeyName, err := initKeyPublic.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of signing key for initializing NV index: %w", err)
	}

	nameAlg := tpm2.HashAlgorithmSHA256

	// The NV index requires 4 policies:
	// - A signed policy for initialization, signed with a key that is discarded so that the index cannot be recreated.
	// - A signed policy for updating the index to revoke old dynamic authorization policies.
	// - A policy for updating the authorization value (PIN / passphrase).
	// - A policy to read the counter value without knowing the authorization value, as the value isn't secret.
	// - A policy to use the count value in a PolicyNV assertion.
	var authPolicies tpm2.DigestList

	trial, _ := tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicyNvWritten(false)
	trial.PolicySigned(initKeyName, nil)
	authPolicies = append(authPolicies, trial.GetDigest())

	trial, _ = tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicyNvWritten(true)
	trial.PolicySigned(updateKeyName, nil)
	authPolicies = append(authPolicies, trial.GetDigest())

	trial, _ = tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	trial.PolicyAuthValue()
	authPolicies = append(authPolicies, trial.GetDigest())

	trial, _ = tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVRead)
	authPolicies = append(authPolicies, trial.GetDigest())

	trial, _ = tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandPolicyNV)
	authPolicies = append(authPolicies, trial.GetDigest())

	trial, _ = tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyOR(authPolicies)

	// Define the NV index
	public := &tpm2.NVPublic{
		Index:      handle,
		NameAlg:    nameAlg,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, public, hmacSession)
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
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, hmacSession)
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
	sig, err := rsa.SignPSS(rand.Reader, initKey, signDigest.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	initKeyContext, err := tpm.LoadExternal(nil, initKeyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot load public part of key used to initialize NV index to the TPM: %w", err)
	}
	defer tpm.FlushContext(initKeyContext)

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: signDigest,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	// Execute the policy assertions
	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyNvWritten(policySession, false); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if _, _, err := tpm.PolicySigned(initKeyContext, policySession, true, nil, nil, 0, &signature); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	if err := tpm.NVIncrement(index, index, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return nil, nil, xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// The index has a different name now that it has been written, so update the public area we return so that it can be used
	// to construct an authorization policy.
	public.Attrs |= tpm2.AttrNVWritten

	succeeded = true
	return public, authPolicies, nil
}

func performPINChange(tpm *tpm2.TPMContext, public *tpm2.NVPublic, authPolicies tpm2.DigestList, oldAuth, newAuth string,
	hmacSession tpm2.SessionContext) error {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(public)
	if err != nil {
		return xerrors.Errorf("cannot create resource context for NV index: %w", err)
	}
	index.SetAuthValue([]byte(oldAuth))

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, public.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVChangeAuth); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}
	if err := tpm.PolicyAuthValue(policySession); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}

	if err := tpm.NVChangeAuth(index, tpm2.Auth(newAuth), policySession, hmacSession.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return xerrors.Errorf("cannot change authorization value for NV index: %w", err)
	}

	return nil
}

func ChangePIN(tpm *TPMConnection, path string, oldAuth, newAuth string) error {
	// Open the key data file
	keyFile, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer keyFile.Close()

	data, _, pinIndexPublic, err := readAndValidateKeyData(tpm.TPMContext, keyFile, nil, tpm.HmacSession())
	if err != nil {
		var kfErr keyFileError
		if xerrors.As(err, &kfErr) {
			return InvalidKeyFileError{err.Error()}
		}
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}

	if err := performPINChange(tpm.TPMContext, pinIndexPublic, data.StaticPolicyData.PinIndexAuthPolicies, oldAuth, newAuth, tpm.HmacSession()); err != nil {
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
