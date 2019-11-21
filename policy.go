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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

var (
	knownDigests = map[tpm2.HashAlgorithmId]struct {
		constructor func() hash.Hash
		size        int
	}{
		tpm2.HashAlgorithmSHA1:   {constructor: sha1.New, size: sha1.Size},
		tpm2.HashAlgorithmSHA256: {constructor: sha256.New, size: sha256.Size},
		tpm2.HashAlgorithmSHA384: {constructor: sha512.New384, size: sha512.Size384},
		tpm2.HashAlgorithmSHA512: {constructor: sha512.New, size: sha512.Size}}
)

type policyComputeInput struct {
	secureBootPCRAlg     tpm2.HashAlgorithmId
	grubPCRAlg           tpm2.HashAlgorithmId
	snapModelPCRAlg      tpm2.HashAlgorithmId
	secureBootPCRDigests tpm2.DigestList
	grubPCRDigests       tpm2.DigestList
	snapModelPCRDigests  tpm2.DigestList
	pinObjectName        tpm2.Name
	pinIndex             tpm2.ResourceContext
	policyRevokeIndex    tpm2.ResourceContext
	policyRevokeCount    uint64
}

type policyData struct {
	Algorithm               tpm2.HashAlgorithmId
	SecureBootPCRAlg        tpm2.HashAlgorithmId
	GrubPCRAlg              tpm2.HashAlgorithmId
	SnapModelPCRAlg         tpm2.HashAlgorithmId
	SecureBootORDigests     tpm2.DigestList
	GrubORDigests           tpm2.DigestList
	SnapModelORDigests      tpm2.DigestList
	PinIndexHandle          tpm2.Handle
	PolicyRevokeIndexHandle tpm2.Handle
	PolicyRevokeCount       uint64
}

func hashAlgToGoHash(hashAlg tpm2.HashAlgorithmId) hash.Hash {
	knownDigest, isKnown := knownDigests[hashAlg]
	if !isKnown {
		panic("Unknown digest algorithm")
	}
	return knownDigest.constructor()
}

func getDigestSize(alg tpm2.HashAlgorithmId) uint {
	known, isKnown := knownDigests[alg]
	if !isKnown {
		panic("Unknown digest algorithm")
	}
	return uint(known.size)
}

func createPolicyRevocationNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, ownerAuth []byte, session *tpm2.Session) (tpm2.ResourceContext, error) {
	public := tpm2.NVPublic{
		Index:   handle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.MakeNVAttributes(tpm2.AttrNVAuthWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeCounter),
		Size:    8}

	if err := tpm.NVDefineSpace(tpm2.HandleOwner, nil, &public, session.WithAuthValue(ownerAuth)); err != nil {
		return nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	context, err := tpm.WrapHandle(handle)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain context for new NV index: %w", err)
	}

	// The name associated with context is read back from the TPM with no integrity protection, so we don't know if it's correct yet.
	// We need to check that it's consistent with the NV index we created before adding it to an authorization policy.

	// Initialize the index. This command is integrity protected so it will fail if the name associated with context doesn't
	// correspond to the NV index. Success here confirms that the name associated with context corresponds to the actual NV index
	// that we created. Calling the ResourceContext.Name() method on it will return a value that can be safely used to compute an
	// authorization policy.
	if err := tpm.NVIncrement(context, context, session); err != nil {
		return nil, xerrors.Errorf("cannot increment new NV index: %w", err)
	}

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

func computePolicy(alg tpm2.HashAlgorithmId, input *policyComputeInput) (*policyData, tpm2.Digest, error) {
	if len(input.secureBootPCRDigests) == 0 {
		return nil, nil, errors.New("no secure-boot digests provided")
	}
	secureBootORDigests := make(tpm2.DigestList, 0)
	for _, digest := range input.secureBootPCRDigests {
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		pcrDigest, pcrs := computePolicyPCRParams(alg, input.secureBootPCRAlg, digest, secureBootPCR)
		trial.PolicyPCR(pcrDigest, pcrs)
		secureBootORDigests = append(secureBootORDigests, trial.GetDigest())
	}

	if len(input.grubPCRDigests) == 0 {
		return nil, nil, fmt.Errorf("no grub digests provided")
	}
	grubORDigests := make(tpm2.DigestList, 0)
	for _, digest := range input.grubPCRDigests {
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		trial.PolicyOR(ensureSufficientORDigests(secureBootORDigests))
		pcrDigest, pcrs := computePolicyPCRParams(alg, input.grubPCRAlg, digest, grubPCR)
		trial.PolicyPCR(pcrDigest, pcrs)
		grubORDigests = append(grubORDigests, trial.GetDigest())
	}

	if len(input.snapModelPCRDigests) == 0 {
		return nil, nil, fmt.Errorf("no snap model digests provided")
	}
	snapModelORDigests := make(tpm2.DigestList, 0)
	for _, digest := range input.snapModelPCRDigests {
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		trial.PolicyOR(ensureSufficientORDigests(grubORDigests))
		pcrDigest, pcrs := computePolicyPCRParams(alg, input.snapModelPCRAlg, digest, snapModelPCR)
		trial.PolicyPCR(pcrDigest, pcrs)
		snapModelORDigests = append(snapModelORDigests, trial.GetDigest())
	}

	trial, _ := tpm2.ComputeAuthPolicy(alg)
	trial.PolicyOR(ensureSufficientORDigests(snapModelORDigests))

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, input.policyRevokeCount)
	trial.PolicyNV(input.policyRevokeIndex.Name(), operandB, 0, tpm2.OpUnsignedLE)

	trial.PolicySecret(input.pinIndex.Name(), nil)

	return &policyData{Algorithm: alg,
		SecureBootPCRAlg:        input.secureBootPCRAlg,
		GrubPCRAlg:              input.grubPCRAlg,
		SnapModelPCRAlg:         input.snapModelPCRAlg,
		SecureBootORDigests:     secureBootORDigests,
		GrubORDigests:           grubORDigests,
		SnapModelORDigests:      snapModelORDigests,
		PinIndexHandle:          input.pinIndex.Handle(),
		PolicyRevokeIndexHandle: input.policyRevokeIndex.Handle(),
		PolicyRevokeCount:       input.policyRevokeCount}, trial.GetDigest(), nil
}

func swallowPolicyORValueError(err error) error {
	switch e := err.(type) {
	case *tpm2.TPMParameterError:
		if e.Code() == tpm2.ErrorValue && e.Command() == tpm2.CommandPolicyOR {
			return nil
		}
	}
	return err
}

func wrapPolicyORError(err error, index int) error {
	return xerrors.Errorf("cannot execute PolicyOR assertion after PolicyPCR assertion against PCR%d: %w", index, err)
}

func wrapPolicyPCRError(err error, index int) error {
	return xerrors.Errorf("cannot execute PolicyPCR assertion against PCR%d: %w", index, err)
}

func executePolicySessionPCRAssertions(tpm *tpm2.TPMContext, sessionContext tpm2.ResourceContext,
	input *policyData) error {
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.SecureBootPCRAlg, secureBootPCR)); err != nil {
		return wrapPolicyPCRError(err, secureBootPCR)
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.SecureBootORDigests)); swallowPolicyORValueError(err) != nil {
		return wrapPolicyORError(err, secureBootPCR)
	}
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.GrubPCRAlg, grubPCR)); err != nil {
		return wrapPolicyPCRError(err, grubPCR)
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.GrubORDigests)); swallowPolicyORValueError(err) != nil {
		return wrapPolicyORError(err, grubPCR)
	}
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.SnapModelPCRAlg, snapModelPCR)); err != nil {
		return wrapPolicyPCRError(err, snapModelPCR)
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.SnapModelORDigests)); swallowPolicyORValueError(err) != nil {
		return wrapPolicyORError(err, snapModelPCR)
	}
	return nil
}

func executePolicySession(tpm *TPMConnection, sessionContext tpm2.ResourceContext, input *policyData, pin string) error {
	if err := executePolicySessionPCRAssertions(tpm.TPMContext, sessionContext, input); err != nil {
		return xerrors.Errorf("cannot execute PCR assertions: %w", err)
	}

	policyRevokeContext, err := tpm.WrapHandle(input.PolicyRevokeIndexHandle)
	if err != nil {
		return xerrors.Errorf("cannot create context for policy revocation NV index: %w", err)
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, input.PolicyRevokeCount)
	if err := tpm.PolicyNV(policyRevokeContext, policyRevokeContext, sessionContext, operandB, 0, tpm2.OpUnsignedLE, nil); err != nil {
		return xerrors.Errorf("cannot execute PolicyNV assertion: %w", err)
	}

	pinIndexContext, err := tpm.WrapHandle(input.PinIndexHandle)
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
