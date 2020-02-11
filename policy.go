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
	"errors"

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
	policyRevokeIndexPub       *tpm2.NVPublic
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
	pinIndexPub *tpm2.NVPublic
}

type staticPolicyData struct {
	Algorithm          tpm2.HashAlgorithmId
	AuthorizeKeyPublic *tpm2.Public
	PinIndexHandle     tpm2.Handle
}

func incrementPolicyRevocationNvIndex(tpm *tpm2.TPMContext, index tpm2.ResourceContext, key *rsa.PrivateKey, keyPublic *tpm2.Public, hmacSession tpm2.SessionContext) error {
	nvPub, _, err := tpm.NVReadPublic(index, hmacSession.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of NV index: %w", err)
	}

	// Begin a policy session to increment the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nvPub.NameAlg, nil)
	if err != nil {
		return xerrors.Errorf("cannot begin policy session: %w", err)
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
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
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
	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
		return xerrors.Errorf("cannot execute PolicyCommandCode assertion: %w", err)
	}
	if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature); err != nil {
		return xerrors.Errorf("cannot execute PolicySigned assertion: %w", err)
	}

	// Increment the index.
	if err := tpm.NVIncrement(index, index, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot increment NV index: %w", err)
	}

	return nil
}

func createPolicyRevocationNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, key *rsa.PrivateKey, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	keyPublic := createPublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of signing key for incrementing NV index: %w", err)
	}

	nameAlg := tpm2.HashAlgorithmSHA256

	trial, _ := tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicySigned(keyName, nil)

	public := &tpm2.NVPublic{
		Index:      handle,
		NameAlg:    nameAlg,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeCounter),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	context, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, public, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), context, session)
	}()

	// Initialize the index.
	if err := incrementPolicyRevocationNvIndex(tpm, context, key, keyPublic, session); err != nil {
		return nil, xerrors.Errorf("cannot initialize new NV index: %w", err)
	}

	// The index has a different name now that it has been written, so update the public area we return so that it can
	// be used to construct a ResourceContext that will work for it.
	public.Attrs |= tpm2.AttrNVWritten

	succeeded = true
	return public, nil
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

	pinIndexName, err := input.pinIndexPub.Name()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot compute name of PIN NV index: %w", err)
	}

	trial.PolicyAuthorize(nil, keyName)
	trial.PolicySecret(pinIndexName, nil)

	return &staticPolicyData{
		Algorithm:          alg,
		AuthorizeKeyPublic: keyPublic,
		PinIndexHandle:     input.pinIndexPub.Index}, key, trial.GetDigest(), nil
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

	policyRevokeIndexName, err := input.policyRevokeIndexPub.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of policy revocation NV index: %w", err)
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, input.policyRevokeCount)
	trial.PolicyNV(policyRevokeIndexName, operandB, 0, tpm2.OpUnsignedLE)

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
		PolicyRevokeIndexHandle:   input.policyRevokeIndexPub.Index,
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

func executePolicySessionPCRAssertions(tpm *tpm2.TPMContext, session tpm2.SessionContext, input *dynamicPolicyData) error {
	if err := tpm.PolicyPCR(session, nil, makePCRSelectionList(input.SecureBootPCRAlg, secureBootPCR)); err != nil {
		return wrapPolicyPCRError(err, secureBootPCR)
	}
	if err := tpm.PolicyOR(session, ensureSufficientORDigests(input.SecureBootORDigests)); err != nil {
		return wrapPolicyORError(err, secureBootPCR)
	}
	if err := tpm.PolicyPCR(session, nil, makePCRSelectionList(input.UbuntuBootParamsPCRAlg, ubuntuBootParamsPCR)); err != nil {
		return wrapPolicyPCRError(err, ubuntuBootParamsPCR)
	}
	if err := tpm.PolicyOR(session, ensureSufficientORDigests(input.UbuntuBootParamsORDigests)); err != nil {
		return wrapPolicyORError(err, ubuntuBootParamsPCR)
	}
	return nil
}

func executePolicySession(tpm *TPMConnection, policySession tpm2.SessionContext, staticInput *staticPolicyData,
	dynamicInput *dynamicPolicyData, pin string) error {
	if err := executePolicySessionPCRAssertions(tpm.TPMContext, policySession, dynamicInput); err != nil {
		return xerrors.Errorf("cannot execute PCR assertions: %w", err)
	}

	policyRevokeContext, err := tpm.CreateResourceContextFromTPM(dynamicInput.PolicyRevokeIndexHandle)
	if err != nil {
		return xerrors.Errorf("cannot create context for dynamic authorization policy revocation NV index: %w", err)
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, dynamicInput.PolicyRevokeCount)
	if err := tpm.PolicyNV(policyRevokeContext, policyRevokeContext, policySession, operandB, 0, tpm2.OpUnsignedLE, nil); err != nil {
		return xerrors.Errorf("dynamic authorization policy revocation check failed: %w", err)
	}

	authorizeKeyContext, err := tpm.LoadExternal(nil, staticInput.AuthorizeKeyPublic, tpm2.HandleOwner)
	if err != nil {
		return xerrors.Errorf("cannot load public area for dynamic authorization policy signature verification key: %w", err)
	}
	defer tpm.FlushContext(authorizeKeyContext)

	if !staticInput.AuthorizeKeyPublic.NameAlg.Supported() {
		return errors.New("public area of dynamic authorization policy signature verification key has an unsupported name algorithm")
	}
	h := staticInput.AuthorizeKeyPublic.NameAlg.NewHash()
	h.Write(dynamicInput.AuthorizedPolicy)

	authorizeTicket, err := tpm.VerifySignature(authorizeKeyContext, h.Sum(nil), dynamicInput.AuthorizedPolicySignature)
	if err != nil {
		return xerrors.Errorf("dynamic authorization policy signature verification failed: %w", err)
	}

	if err := tpm.PolicyAuthorize(policySession, dynamicInput.AuthorizedPolicy, nil, authorizeKeyContext.Name(), authorizeTicket); err != nil {
		return xerrors.Errorf("dynamic authorization policy check failed: %w", err)
	}

	pinIndexContext, err := tpm.CreateResourceContextFromTPM(staticInput.PinIndexHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for PIN NV index: %w", err)
	}
	pinIndexContext.SetAuthValue([]byte(pin))
	// Use the HMAC session created when the connection was opened rather than creating a new one.
	if _, _, err := tpm.PolicySecret(pinIndexContext, policySession, nil, nil, 0, tpm.HmacSession()); err != nil {
		return xerrors.Errorf("cannot execute PolicySecret assertion: %w", err)
	}

	return nil
}

func lockAccessUntilTPMReset(tpm *tpm2.TPMContext, input *staticPolicyData) error {
	pinIndexContext, err := tpm.CreateResourceContextFromTPM(input.PinIndexHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for pin NV index: %w", err)
	}
	if err := tpm.NVReadLock(pinIndexContext, pinIndexContext, nil); err != nil {
		return xerrors.Errorf("cannot readlock pin NV index: %w", err)
	}
	return nil
}
