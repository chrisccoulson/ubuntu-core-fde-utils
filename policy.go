package fdeutil

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"

	"github.com/chrisccoulson/go-tpm2"
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

const (
	secureBootPCR = 7
	grubPCR       = 8
	snapModelPCR  = 11
)

type policySecretError struct {
	err error
}

func (e policySecretError) Error() string {
	return fmt.Sprintf("cannot execute PolicySecret command: %v", e.err)
}

type compoundSbPolicyComputeInput struct {
	secureBootPCRAlg     tpm2.AlgorithmId
	grubPCRAlg           tpm2.AlgorithmId
	secureBootPCRDigests tpm2.DigestList
	grubPCRDigests       tpm2.DigestList
}

type policyComputeInput struct {
	compoundSbPolicies  []compoundSbPolicyComputeInput
	snapModelPCRAlg     tpm2.AlgorithmId
	snapModelPCRDigests tpm2.DigestList
	pinObjectName       tpm2.Name
}

type compoundSbPolicyData struct {
	SecureBootPCRAlg    tpm2.AlgorithmId
	GrubPCRAlg          tpm2.AlgorithmId
	SecureBootORDigests tpm2.DigestList
	GrubORDigests       tpm2.DigestList
}

type policyData struct {
	Algorithm          tpm2.AlgorithmId
	SbPolicyData       []compoundSbPolicyData
	SbPolicyORDigests  tpm2.DigestList
	SnapModelPCRAlg    tpm2.AlgorithmId
	SnapModelORDigests tpm2.DigestList
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

func initTrialPolicyDigest(alg tpm2.AlgorithmId) tpm2.Digest {
	digestSize := getDigestSize(alg)
	return make(tpm2.Digest, digestSize)
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

func computePCRDigest(alg tpm2.AlgorithmId, pcrs tpm2.PCRSelectionList, digests tpm2.DigestList) tpm2.Digest {
	h := hashAlgToGoHash(alg)
	j := 0
	for _, selection := range pcrs {
		sel := selection.Select
		sort.Ints(sel)
		for _ = range sel {
			h.Write(digests[j])
			j++
		}
	}
	return h.Sum(nil)
}

func trialPolicyPCR(alg tpm2.AlgorithmId, currentDigest tpm2.Digest, pcrs tpm2.PCRSelectionList,
	pcrDigest tpm2.Digest) (tpm2.Digest, error) {
	h := hashAlgToGoHash(alg)
	h.Write(currentDigest)
	binary.Write(h, binary.BigEndian, tpm2.CommandPolicyPCR)
	if err := tpm2.MarshalToWriter(h, pcrs); err != nil {
		return nil, fmt.Errorf("cannot marshal pcrs: %v", err)
	}
	h.Write(pcrDigest)

	return h.Sum(nil), nil
}

func trialPolicyOR(alg tpm2.AlgorithmId, pHashList tpm2.DigestList) (tpm2.Digest, error) {
	if len(pHashList) > 8 {
		return nil, errors.New("cannot have more than 8 digests in a PolicyOR")
	}
	digests := new(bytes.Buffer)
	for _, digest := range pHashList {
		digests.Write(digest)
	}
	resetPolicyDigest := initTrialPolicyDigest(alg)

	h := hashAlgToGoHash(alg)
	h.Write(resetPolicyDigest)
	binary.Write(h, binary.BigEndian, tpm2.CommandPolicyOR)
	digests.WriteTo(h)

	return h.Sum(nil), nil
}

func trialPolicySecret(alg tpm2.AlgorithmId, currentDigest tpm2.Digest, name tpm2.Name,
	policyRef tpm2.Nonce) tpm2.Digest {
	h := hashAlgToGoHash(alg)
	h.Write(currentDigest)
	binary.Write(h, binary.BigEndian, tpm2.CommandPolicySecret)
	h.Write(name)

	intermediateDigest := h.Sum(nil)

	h = hashAlgToGoHash(alg)
	h.Write(intermediateDigest)
	h.Write(policyRef)

	return h.Sum(nil)
}

func computeCompoundSbPolicy(alg tpm2.AlgorithmId, input *compoundSbPolicyComputeInput) (*compoundSbPolicyData,
	tpm2.Digest, error) {
	if len(input.secureBootPCRDigests) == 0 {
		return nil, nil, errors.New("no secure-boot digests provided")
	}
	secureBootORDigests := make(tpm2.DigestList, 0)
	for i, digest := range input.secureBootPCRDigests {
		policyDigest := initTrialPolicyDigest(alg)
		pcrs := makePCRSelectionList(input.secureBootPCRAlg, secureBootPCR)
		pcrDigest := computePCRDigest(alg, pcrs, tpm2.DigestList{digest})
		policyDigest, err := trialPolicyPCR(alg, policyDigest, pcrs, pcrDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot execute PolicyPCR with secure-boot digest at index "+
				"%d: %v", i, err)
		}
		secureBootORDigests = append(secureBootORDigests, policyDigest)
	}

	if len(input.grubPCRDigests) == 0 {
		return nil, nil, fmt.Errorf("no grub digests provided")
	}
	grubORDigests := make(tpm2.DigestList, 0)
	for i, digest := range input.grubPCRDigests {
		policyDigest := initTrialPolicyDigest(alg)
		policyDigest, err := trialPolicyOR(alg, ensureSufficientORDigests(secureBootORDigests))
		if err != nil {
			return nil, nil, fmt.Errorf("cannot execute PolicyOR of secure-boot policy digests: %v",
				err)
		}
		pcrs := makePCRSelectionList(input.grubPCRAlg, grubPCR)
		pcrDigest := computePCRDigest(alg, pcrs, tpm2.DigestList{digest})
		policyDigest, err = trialPolicyPCR(alg, policyDigest, pcrs, pcrDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot execute PolicyPCR with grub digest at index "+
				"%d: %v", i, err)
		}
		grubORDigests = append(grubORDigests, policyDigest)
	}

	policy := initTrialPolicyDigest(alg)
	policy, err := trialPolicyOR(alg, ensureSufficientORDigests(grubORDigests))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot execute PolicyOR of grub policy digests: %v", err)
	}

	return &compoundSbPolicyData{
		SecureBootPCRAlg:    input.secureBootPCRAlg,
		GrubPCRAlg:          input.grubPCRAlg,
		SecureBootORDigests: secureBootORDigests,
		GrubORDigests:       grubORDigests}, policy, nil
}

func computePolicy(alg tpm2.AlgorithmId, input *policyComputeInput) (*policyData, tpm2.Digest, error) {
	if len(input.compoundSbPolicies) == 0 {
		return nil, nil, fmt.Errorf("cannot generate policy: no compound secure-boot policies provided")
	}

	sbPolicyDatas := make([]compoundSbPolicyData, 0)
	sbPolicyORDigests := make(tpm2.DigestList, 0)
	for i, policy := range input.compoundSbPolicies {
		out, digest, err := computeCompoundSbPolicy(alg, &policy)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot compute compound secure-boot policy at index "+
				"%d: %v", i, err)
		}
		sbPolicyDatas = append(sbPolicyDatas, *out)
		sbPolicyORDigests = append(sbPolicyORDigests, digest)
	}

	snapModelORDigests := make(tpm2.DigestList, 0)
	for i, digest := range input.snapModelPCRDigests {
		policyDigest := initTrialPolicyDigest(alg)
		policyDigest, err := trialPolicyOR(alg, ensureSufficientORDigests(sbPolicyORDigests))
		if err != nil {
			return nil, nil, fmt.Errorf("cannot execute PolicyOR of compound secure-boot policy "+
				"digests: %v", err)
		}
		pcrs := makePCRSelectionList(input.snapModelPCRAlg, snapModelPCR)
		pcrDigest := computePCRDigest(alg, pcrs, tpm2.DigestList{digest})
		policyDigest, err = trialPolicyPCR(alg, policyDigest, pcrs, pcrDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot execute PolicyPCR with snap model digest at index "+
				"%d: %v", i, err)
		}
		snapModelORDigests = append(snapModelORDigests, policyDigest)
	}

	policy, err := trialPolicyOR(alg, ensureSufficientORDigests(snapModelORDigests))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot execute PolicyOR of snap model digests: %v", err)
	}
	policy = trialPolicySecret(alg, policy, input.pinObjectName, nil)

	return &policyData{Algorithm: alg,
		SbPolicyData:       sbPolicyDatas,
		SbPolicyORDigests:  sbPolicyORDigests,
		SnapModelPCRAlg:    input.snapModelPCRAlg,
		SnapModelORDigests: snapModelORDigests}, policy, nil
}

func tryExecCompoundSbPolicy(tpm tpm2.TPMContext, sessionContext tpm2.ResourceContext,
	input *compoundSbPolicyData) error {
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.SecureBootPCRAlg,
		secureBootPCR)); err != nil {
		return err
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.SecureBootORDigests)); err != nil {
		return err
	}
	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.GrubPCRAlg, grubPCR)); err != nil {
		return err
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.GrubORDigests)); err != nil {
		return err
	}
	return nil
}

func executePolicySession(tpm tpm2.TPMContext, sessionContext, pinContext tpm2.ResourceContext, input *policyData,
	pin string) error {
	for _, policy := range input.SbPolicyData {
		if err := tryExecCompoundSbPolicy(tpm, sessionContext, &policy); err == nil {
			if err := tpm.PolicyOR(sessionContext,
				ensureSufficientORDigests(input.SbPolicyORDigests)); err == nil {
				break
			}
		}
		if err := tpm.PolicyRestart(sessionContext); err != nil {
			return fmt.Errorf("unable to restart after a failed sub-policy attempt: %v", err)
		}
	}

	if err := tpm.PolicyPCR(sessionContext, nil, makePCRSelectionList(input.SnapModelPCRAlg,
		snapModelPCR)); err != nil {
		return fmt.Errorf("cannot execute PolicyPCR with snap model register: %v", err)
	}
	if err := tpm.PolicyOR(sessionContext, ensureSufficientORDigests(input.SnapModelORDigests)); err != nil {
		paramErr, isParamErr := err.(tpm2.TPMParameterError)
		if !isParamErr || paramErr.Code != tpm2.ErrorValue {
			return fmt.Errorf("cannot execute PolicyOR with snap model policy digests: %v", err)
		}
	}

	pinSessionContext, err := tpm.StartAuthSession(nil, pinContext, tpm2.SessionTypeHMAC, nil,
		defaultHashAlgorithm, []byte(pin))
	if err != nil {
		return fmt.Errorf("cannot start HMAC session for PIN verification: %v", err)
	}
	defer tpm.FlushContext(pinSessionContext)

	pinSession := tpm2.Session{Context: pinSessionContext}
	if _, _, err := tpm.PolicySecret(pinContext, sessionContext, nil, nil, 0, &pinSession); err != nil {
		return policySecretError{err: err}
	}

	return nil
}
