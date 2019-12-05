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

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

type dynamicPolicyComputeParams struct {
	key                        *rsa.PrivateKey
	signAlg                    tpm2.HashAlgorithmId
	secureBootPCRAlg           tpm2.HashAlgorithmId
	ubuntuBootParamsPCRAlg     tpm2.HashAlgorithmId
	secureBootPCRDigests       tpm2.DigestList
	ubuntuBootParamsPCRDigests tpm2.DigestList
	policyRevokeIndex          tpm2.ResourceContext
	policyRevokeCount          uint64
}

type dynamicPolicyData struct {
	SecureBootPCRAlg          tpm2.HashAlgorithmId
	UbuntuBootParamsPCRAlg    tpm2.HashAlgorithmId
	SecureBootORDigests       tpm2.DigestList
	UbuntuBootParamsORDigests tpm2.DigestList
	PolicyRevokeIndexHandle   tpm2.Handle
	PolicyRevokeCount         uint64
	AuthorizedPolicy          tpm2.Digest
	AuthorizedPolicySignature *tpm2.Signature
}

type staticPolicyComputeParams struct {
	pinIndex tpm2.ResourceContext
}

type staticPolicyData struct {
	Algorithm          tpm2.HashAlgorithmId
	AuthorizeKeyPublic *tpm2.Public
	PinIndexHandle     tpm2.Handle
}

func incrementPolicyRevocationNvIndex(tpm *tpm2.TPMContext, index tpm2.ResourceContext, key *rsa.PrivateKey, keyPublic *tpm2.Public, session *tpm2.Session) error {
	nvPub, _, err := tpm.NVReadPublic(index, session.AddAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of NV index: %w", err)
	}

	// Begin a policy session to increment the index.
	policySessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nvPub.NameAlg, nil)
	if err != nil {
		return xerrors.Errorf("cannot begin policy session: %w", err)
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
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, _, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return xerrors.Errorf("cannot load public part of key used to verify authorization signature: %w", err)
	}
	defer tpm.FlushContext(keyLoaded)

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: signDigest,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	// Execute the policy assertions
	if err := tpm.PolicyCommandCode(policySessionContext, tpm2.CommandNVIncrement); err != nil {
		return xerrors.Errorf("cannot execute PolicyCommandCode assertion: %w", err)
	}
	if _, _, err := tpm.PolicySigned(keyLoaded, policySessionContext, true, nil, nil, 0, &signature); err != nil {
		return xerrors.Errorf("cannot execute PolicySigned assertion: %w", err)
	}

	// Increment the index.
	if err := tpm.NVIncrement(index, index, &tpm2.Session{Context: policySessionContext}, session.AddAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot increment NV index: %w", err)
	}

	return nil
}

func createPolicyRevocationNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, key *rsa.PrivateKey, ownerAuth []byte, session *tpm2.Session) (tpm2.ResourceContext, error) {
	keyPublic := createPublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of signing key for incrementing NV index: %w", err)
	}

	nameAlg := tpm2.HashAlgorithmSHA256

	trial, _ := tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicySigned(keyName, nil)

	public := tpm2.NVPublic{
		Index:      handle,
		NameAlg:    nameAlg,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeCounter),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	if err := tpm.NVDefineSpace(tpm2.HandleOwner, nil, &public, session.WithAuthValue(ownerAuth)); err != nil {
		return nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	context, err := tpm.WrapHandle(handle)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain context for new NV index: %w", err)
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm2.HandleOwner, context, session.WithAuthValue(ownerAuth))
	}()

	// The name associated with context is read back from the TPM with no integrity protection, so we don't know if it's correct yet.
	// We need to check that it's consistent with the NV index we created before adding it to an authorization policy.

	expectedName, err := public.Name()
	if err != nil {
		panic(fmt.Sprintf("cannot compute name of NV index: %v", err))
	}
	if !bytes.Equal(expectedName, context.Name()) {
		return nil, errors.New("context for new NV index has unexpected name")
	}

	// The name associated with context is the one associated with the index we created. Initialize the index
	if err := incrementPolicyRevocationNvIndex(tpm, context, key, keyPublic, session); err != nil {
		return nil, xerrors.Errorf("cannot initialize new NV index: %w", err)
	}

	succeeded = true
	return context, nil
}

func ensureSufficientORDigests(digests tpm2.DigestList) tpm2.DigestList {
	if len(digests) == 0 {
		// This is really an error - return nothing here and let the consumer of this handle the error
		return digests
	}
	if len(digests) > 1 {
		return digests
	}
	return tpm2.DigestList{digests[0], digests[0]}
}

func makePCRSelectionList(alg tpm2.HashAlgorithmId, index int) tpm2.PCRSelectionList {
	return tpm2.PCRSelectionList{
		tpm2.PCRSelection{Hash: alg, Select: tpm2.PCRSelectionData{index}}}
}

func computePolicyPCRParams(policyAlg, pcrAlg tpm2.HashAlgorithmId, digest tpm2.Digest, index int) (tpm2.Digest, tpm2.PCRSelectionList) {
	pcrs := makePCRSelectionList(pcrAlg, index)

	pcrValues := make(tpm2.PCRValues)
	pcrValues.EnsureBank(pcrAlg)
	pcrValues[pcrAlg][index] = digest
	pcrDigest, _ := tpm2.ComputePCRDigest(policyAlg, pcrs, pcrValues)

	return pcrDigest, pcrs
}

func computeStaticPolicy(alg tpm2.HashAlgorithmId, input *staticPolicyComputeParams) (*staticPolicyData, *rsa.PrivateKey, tpm2.Digest, error) {
	trial, _ := tpm2.ComputeAuthPolicy(alg)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot generate RSA key pair for policy authorization: %w", err)
	}

	keyPublic := createPublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot compute name of signing key for policy authorization: %w", err)
	}

	trial.PolicyAuthorize(nil, keyName)
	trial.PolicySecret(input.pinIndex.Name(), nil)

	return &staticPolicyData{
		Algorithm:          alg,
		AuthorizeKeyPublic: keyPublic,
		PinIndexHandle:     input.pinIndex.Handle()}, key, trial.GetDigest(), nil
}

func computeDynamicPolicy(alg tpm2.HashAlgorithmId, input *dynamicPolicyComputeParams) (*dynamicPolicyData, error) {
	if len(input.secureBootPCRDigests) == 0 {
		return nil, errors.New("no secure-boot digests provided")
	}
	secureBootORDigests := make(tpm2.DigestList, 0)
	for _, digest := range input.secureBootPCRDigests {
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		pcrDigest, pcrs := computePolicyPCRParams(alg, input.secureBootPCRAlg, digest, secureBootPCR)
		trial.PolicyPCR(pcrDigest, pcrs)
		secureBootORDigests = append(secureBootORDigests, trial.GetDigest())
	}

	if len(input.ubuntuBootParamsPCRDigests) == 0 {
		return nil, errors.New("no ubuntu boot params digests provided")
	}
	ubuntuBootParamsORDigests := make(tpm2.DigestList, 0)
	for _, digest := range input.ubuntuBootParamsPCRDigests {
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		trial.PolicyOR(ensureSufficientORDigests(secureBootORDigests))
		pcrDigest, pcrs := computePolicyPCRParams(alg, input.ubuntuBootParamsPCRAlg, digest, ubuntuBootParamsPCR)
		trial.PolicyPCR(pcrDigest, pcrs)
		ubuntuBootParamsORDigests = append(ubuntuBootParamsORDigests, trial.GetDigest())
	}

	trial, _ := tpm2.ComputeAuthPolicy(alg)
	trial.PolicyOR(ensureSufficientORDigests(ubuntuBootParamsORDigests))

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, input.policyRevokeCount)
	trial.PolicyNV(input.policyRevokeIndex.Name(), operandB, 0, tpm2.OpUnsignedLE)

	authorizedPolicy := trial.GetDigest()

	// Create a digest to sign
	h := input.signAlg.NewHash()
	h.Write(authorizedPolicy)

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, input.key, input.signAlg.GetHash(), h.Sum(nil),
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: input.signAlg,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	return &dynamicPolicyData{
		SecureBootPCRAlg:          input.secureBootPCRAlg,
		UbuntuBootParamsPCRAlg:    input.ubuntuBootParamsPCRAlg,
		SecureBootORDigests:       secureBootORDigests,
		UbuntuBootParamsORDigests: ubuntuBootParamsORDigests,
		PolicyRevokeIndexHandle:   input.policyRevokeIndex.Handle(),
		PolicyRevokeCount:         input.policyRevokeCount,
		AuthorizedPolicy:          authorizedPolicy,
		AuthorizedPolicySignature: &signature}, nil
}

func wrapPolicyORError(err error, index int) error {
	return xerrors.Errorf("cannot execute PolicyOR assertion after PolicyPCR assertion against PCR%d: %w", index, err)
}

func wrapPolicyPCRError(err error, index int) error {
	return xerrors.Errorf("cannot execute PolicyPCR assertion against PCR%d: %w", index, err)
}

func executePolicySessionPCRAssertions(tpm *tpm2.TPMContext, sessionContext tpm2.ResourceContext, input *dynamicPolicyData) error {
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.SecureBootPCRAlg, secureBootPCR)); err != nil {
		return wrapPolicyPCRError(err, secureBootPCR)
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.SecureBootORDigests)); err != nil {
		return wrapPolicyORError(err, secureBootPCR)
	}
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.UbuntuBootParamsPCRAlg, ubuntuBootParamsPCR)); err != nil {
		return wrapPolicyPCRError(err, ubuntuBootParamsPCR)
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.UbuntuBootParamsORDigests)); err != nil {
		return wrapPolicyORError(err, ubuntuBootParamsPCR)
	}
	return nil
}

func executePolicySession(tpm *TPMConnection, sessionContext tpm2.ResourceContext, staticInput *staticPolicyData,
	dynamicInput *dynamicPolicyData, pin string) error {
	if err := executePolicySessionPCRAssertions(tpm.TPMContext, sessionContext, dynamicInput); err != nil {
		return xerrors.Errorf("cannot execute PCR assertions: %w", err)
	}

	policyRevokeContext, err := tpm.WrapHandle(dynamicInput.PolicyRevokeIndexHandle)
	if err != nil {
		return xerrors.Errorf("cannot create context for dynamic authorization policy revocation NV index: %w", err)
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, dynamicInput.PolicyRevokeCount)
	if err := tpm.PolicyNV(policyRevokeContext, policyRevokeContext, sessionContext, operandB, 0, tpm2.OpUnsignedLE, nil); err != nil {
		return xerrors.Errorf("dynamic authorization policy revocation check failed: %w", err)
	}

	authorizeKeyContext, authorizeKeyName, err := tpm.LoadExternal(nil, staticInput.AuthorizeKeyPublic, tpm2.HandleOwner)
	if err != nil {
		return xerrors.Errorf("cannot load public area for dynamic authorization policy signature verification: %w", err)
	}
	defer tpm.FlushContext(authorizeKeyContext)

	h := staticInput.AuthorizeKeyPublic.NameAlg.NewHash()
	h.Write(dynamicInput.AuthorizedPolicy)

	authorizeTicket, err := tpm.VerifySignature(authorizeKeyContext, h.Sum(nil), dynamicInput.AuthorizedPolicySignature)
	if err != nil {
		return xerrors.Errorf("dynamic authorization policy signature verification failed: %w", err)
	}

	if err := tpm.PolicyAuthorize(sessionContext, dynamicInput.AuthorizedPolicy, nil, authorizeKeyName, authorizeTicket); err != nil {
		return xerrors.Errorf("dynamic authorization policy check failed: %w", err)
	}

	pinIndexContext, err := tpm.WrapHandle(staticInput.PinIndexHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for PIN NV index: %w", err)
	}
	// Use the HMAC session created when the connection was opened rather than creating a new one.
	pinSession := tpm.HmacSession()
	if _, _, err := tpm.PolicySecret(pinIndexContext, sessionContext, nil, nil, 0, pinSession.WithAuthValue([]byte(pin))); err != nil {
		return xerrors.Errorf("cannot execute PolicySecret assertion: %w", err)
	}

	return nil
}
