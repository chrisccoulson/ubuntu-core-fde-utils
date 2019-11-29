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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

type policyComputeInput struct {
	secureBootPCRAlg           tpm2.HashAlgorithmId
	ubuntuBootParamsPCRAlg     tpm2.HashAlgorithmId
	secureBootPCRDigests       tpm2.DigestList
	ubuntuBootParamsPCRDigests tpm2.DigestList
	pinObjectName              tpm2.Name
	pinIndex                   tpm2.ResourceContext
	policyRevokeIndex          tpm2.ResourceContext
	policyRevokeCount          uint64
}

type policyData struct {
	Algorithm                 tpm2.HashAlgorithmId
	SecureBootPCRAlg          tpm2.HashAlgorithmId
	UbuntuBootParamsPCRAlg    tpm2.HashAlgorithmId
	SecureBootORDigests       tpm2.DigestList
	UbuntuBootParamsORDigests tpm2.DigestList
	PinIndexHandle            tpm2.Handle
	PolicyRevokeIndexHandle   tpm2.Handle
	PolicyRevokeCount         uint64
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
	if err := tpm.NVIncrement(context, context, session); err != nil {
		return nil, xerrors.Errorf("cannot increment new NV index: %w", err)
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

	if len(input.ubuntuBootParamsPCRDigests) == 0 {
		return nil, nil, fmt.Errorf("no ubuntu boot params digests provided")
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

	trial.PolicySecret(input.pinIndex.Name(), nil)

	return &policyData{Algorithm: alg,
		SecureBootPCRAlg:          input.secureBootPCRAlg,
		UbuntuBootParamsPCRAlg:    input.ubuntuBootParamsPCRAlg,
		SecureBootORDigests:       secureBootORDigests,
		UbuntuBootParamsORDigests: ubuntuBootParamsORDigests,
		PinIndexHandle:            input.pinIndex.Handle(),
		PolicyRevokeIndexHandle:   input.policyRevokeIndex.Handle(),
		PolicyRevokeCount:         input.policyRevokeCount}, trial.GetDigest(), nil
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
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.UbuntuBootParamsPCRAlg, ubuntuBootParamsPCR)); err != nil {
		return wrapPolicyPCRError(err, ubuntuBootParamsPCR)
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.UbuntuBootParamsORDigests)); swallowPolicyORValueError(err) != nil {
		return wrapPolicyORError(err, ubuntuBootParamsPCR)
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
