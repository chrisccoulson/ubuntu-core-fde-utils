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
	knownDigests = map[tpm2.AlgorithmId]struct {
		constructor func() hash.Hash
		size        int
	}{
		tpm2.AlgorithmSHA1:   {constructor: sha1.New, size: sha1.Size},
		tpm2.AlgorithmSHA256: {constructor: sha256.New, size: sha256.Size},
		tpm2.AlgorithmSHA384: {constructor: sha512.New384, size: sha512.Size384},
		tpm2.AlgorithmSHA512: {constructor: sha512.New, size: sha512.Size}}
)

type policyComputeInput struct {
	secureBootPCRAlg     tpm2.AlgorithmId
	grubPCRAlg           tpm2.AlgorithmId
	snapModelPCRAlg      tpm2.AlgorithmId
	secureBootPCRDigests tpm2.DigestList
	grubPCRDigests       tpm2.DigestList
	snapModelPCRDigests  tpm2.DigestList
	pinObjectName        tpm2.Name
	pinIndex             tpm2.ResourceContext
	policyRevokeIndex    tpm2.ResourceContext
	policyRevokeCount    uint64
}

type policyData struct {
	Algorithm               tpm2.AlgorithmId
	SecureBootPCRAlg        tpm2.AlgorithmId
	GrubPCRAlg              tpm2.AlgorithmId
	SnapModelPCRAlg         tpm2.AlgorithmId
	SecureBootORDigests     tpm2.DigestList
	GrubORDigests           tpm2.DigestList
	SnapModelORDigests      tpm2.DigestList
	PinIndexHandle          tpm2.Handle
	PolicyRevokeIndexHandle tpm2.Handle
	PolicyRevokeCount       uint64
}

func hashAlgToGoHash(hashAlg tpm2.AlgorithmId) hash.Hash {
	knownDigest, isKnown := knownDigests[hashAlg]
	if !isKnown {
		panic("Unknown digest algorithm")
	}
	return knownDigest.constructor()
}

func getDigestSize(alg tpm2.AlgorithmId) uint {
	known, isKnown := knownDigests[alg]
	if !isKnown {
		panic("Unknown digest algorithm")
	}
	return uint(known.size)
}

func createPolicyRevocationNvIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, ownerAuth interface{}) (tpm2.ResourceContext, error) {
	public := tpm2.NVPublic{
		Index:   handle,
		NameAlg: tpm2.AlgorithmSHA256,
		Attrs:   tpm2.MakeNVAttributes(tpm2.AttrNVAuthWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeCounter),
		Size:    8}

	if err := tpm.NVDefineSpace(tpm2.HandleOwner, nil, &public, ownerAuth); err != nil {
		return nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	context, err := tpm.WrapHandle(handle)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain context for new NV index: %w", err)
	}

	if err := tpm.NVIncrement(context, context, nil); err != nil {
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

func makePCRSelectionList(alg tpm2.AlgorithmId, index int) tpm2.PCRSelectionList {
	return tpm2.PCRSelectionList{
		tpm2.PCRSelection{Hash: alg, Select: tpm2.PCRSelectionData{index}}}
}

func computePCRDigest(alg tpm2.AlgorithmId, digests tpm2.DigestList) tpm2.Digest {
	h := hashAlgToGoHash(alg)
	for _, d := range digests {
		h.Write(d)
	}
	return h.Sum(nil)
}

func computePolicy(alg tpm2.AlgorithmId, input *policyComputeInput) (*policyData, tpm2.Digest, error) {
	if len(input.secureBootPCRDigests) == 0 {
		return nil, nil, errors.New("no secure-boot digests provided")
	}
	secureBootORDigests := make(tpm2.DigestList, 0)
	for _, digest := range input.secureBootPCRDigests {
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		pcrs := makePCRSelectionList(input.secureBootPCRAlg, secureBootPCR)
		pcrDigest := computePCRDigest(alg, tpm2.DigestList{digest})
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
		pcrs := makePCRSelectionList(input.grubPCRAlg, grubPCR)
		pcrDigest := computePCRDigest(alg, tpm2.DigestList{digest})
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
		pcrs := makePCRSelectionList(input.snapModelPCRAlg, snapModelPCR)
		pcrDigest := computePCRDigest(alg, tpm2.DigestList{digest})
		trial.PolicyPCR(pcrDigest, pcrs)
		snapModelORDigests = append(snapModelORDigests, trial.GetDigest())
	}

	trial, _ := tpm2.ComputeAuthPolicy(alg)
	trial.PolicyOR(ensureSufficientORDigests(snapModelORDigests))

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, input.policyRevokeCount)
	trial.PolicyNV(input.policyRevokeIndex, operandB, 0, tpm2.OpUnsignedLE)

	trial.PolicySecret(input.pinIndex, nil)

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
		if e.Code == tpm2.ErrorValue && e.Command == tpm2.CommandPolicyOR {
			return nil
		}
	}
	return err
}

func wrapPolicyORError(err error, index int) error {
	return fmt.Errorf("cannot execute PolicyOR assertion after PolicyPCR assertion against PCR%d: %v",
		index, err)
}

func wrapPolicyPCRError(err error, index int) error {
	return fmt.Errorf("cannot execute PolicyPCR assertion against PCR%d: %v", index, err)
}

func executePolicySessionPCRAssertions(tpm *tpm2.TPMContext, sessionContext tpm2.ResourceContext,
	input *policyData) error {
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.SecureBootPCRAlg,
		secureBootPCR)); err != nil {
		return wrapPolicyPCRError(err, secureBootPCR)
	}
	if err := tpm.PolicyOR(sessionContext,
		ensureSufficientORDigests(input.SecureBootORDigests)); swallowPolicyORValueError(err) != nil {
		return wrapPolicyORError(err, secureBootPCR)
	}
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.GrubPCRAlg, grubPCR)); err != nil {
		return wrapPolicyPCRError(err, grubPCR)
	}
	if err := tpm.PolicyOR(sessionContext,
		ensureSufficientORDigests(input.GrubORDigests)); swallowPolicyORValueError(err) != nil {
		return wrapPolicyORError(err, grubPCR)
	}
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.SnapModelPCRAlg,
		snapModelPCR)); err != nil {
		return wrapPolicyPCRError(err, snapModelPCR)
	}
	if err := tpm.PolicyOR(sessionContext,
		ensureSufficientORDigests(input.SnapModelORDigests)); swallowPolicyORValueError(err) != nil {
		return wrapPolicyORError(err, snapModelPCR)
	}
	return nil
}

func executePolicySession(tpm *tpm2.TPMContext, sessionContext tpm2.ResourceContext, input *policyData,
	pin string) error {
	if err := executePolicySessionPCRAssertions(tpm, sessionContext, input); err != nil {
		return fmt.Errorf("cannot execute PCR assertions: %v", err)
	}

	policyRevokeContext, err := tpm.WrapHandle(input.PolicyRevokeIndexHandle)
	if err != nil {
		return fmt.Errorf("cannot create context for policy revocation NV index: %v", err)
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, input.PolicyRevokeCount)
	if err := tpm.PolicyNV(policyRevokeContext, policyRevokeContext, sessionContext, operandB, 0,
		tpm2.OpUnsignedLE, nil); err != nil {
		switch e := err.(type) {
		case *tpm2.TPMError:
			if e.Code == tpm2.ErrorPolicy {
				return ErrPolicyRevoked
			}
		}
		return fmt.Errorf("cannot execute PolicyNV assertion: %v", err)
	}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return fmt.Errorf("cannot obtain context for SRK: %v", err)
	}
	pinIndexContext, err := tpm.WrapHandle(input.PinIndexHandle)
	if err != nil {
		return fmt.Errorf("cannot obtain context for PIN NV index: %v", err)
	}

	pinSessionContext, err := tpm.StartAuthSession(srkContext, pinIndexContext, tpm2.SessionTypeHMAC, nil,
		defaultHashAlgorithm, []byte(pin))
	if err != nil {
		return fmt.Errorf("cannot start HMAC session for PIN verification: %v", err)
	}
	defer tpm.FlushContext(pinSessionContext)

	pinSession := tpm2.Session{Context: pinSessionContext}
	if _, _, err := tpm.PolicySecret(pinIndexContext, sessionContext, nil, nil, 0, &pinSession); err != nil {
		switch e := err.(type) {
		case *tpm2.TPMSessionError:
			if e.Code == tpm2.ErrorAuthFail {
				return ErrPinFail
			}
		}
		return fmt.Errorf("cannot execute PolicySecret assertion: %v", err)
	}

	return nil
}
