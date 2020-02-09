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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"math/big"
	"testing"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

type mockResourceContext struct {
	name   tpm2.Name
	handle tpm2.Handle
}

func (c *mockResourceContext) Name() tpm2.Name {
	return c.name
}

func (c *mockResourceContext) Handle() tpm2.Handle {
	return c.handle
}

func TestComputeStaticPolicy(t *testing.T) {
	pinIndexPub := &tpm2.NVPublic{
		Index:      testCreationParams.PinHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead|tpm2.AttrNVReadStClear, tpm2.NVTypeOrdinary),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       0}
	pinName, _ := pinIndexPub.Name()

	lockIndexPub := tpm2.NVPublic{
		Index:      lockNVHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead|tpm2.AttrNVNoDA|tpm2.AttrNVReadStClear|tpm2.AttrNVWritten, tpm2.NVTypeOrdinary),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       0}
	lockName, _ := lockIndexPub.Name()

	for _, data := range []struct {
		desc string
		alg  tpm2.HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  tpm2.HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  tpm2.HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, key, policy, err := computeStaticPolicy(data.alg, &staticPolicyComputeParams{pinIndexPub: pinIndexPub, lockIndexName: lockName})
			if err != nil {
				t.Fatalf("computeStaticPolicy failed: %v", err)
			}
			if dataout.Algorithm != data.alg {
				t.Errorf("Unexpected session algorithm: %v", err)
			}
			if dataout.AuthorizeKeyPublic.Params.RSADetail().Exponent != uint32(key.PublicKey.E) {
				t.Errorf("Auth key public area has wrong exponent")
			}
			if dataout.AuthorizeKeyPublic.Params.RSADetail().KeyBits != uint16(key.PublicKey.N.BitLen()) {
				t.Errorf("Auth key public area has wrong bit length")
			}
			if !bytes.Equal(dataout.AuthorizeKeyPublic.Unique.RSA(), key.PublicKey.N.Bytes()) {
				t.Errorf("Auth key public area has wrong modulus")
			}

			h := dataout.AuthorizeKeyPublic.NameAlg.NewHash()
			h.Write(make(tpm2.Digest, data.alg.Size()))

			sig, err := rsa.SignPSS(rand.Reader, key, dataout.AuthorizeKeyPublic.NameAlg.GetHash(), h.Sum(nil),
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Errorf("SignPSS failed: %v", err)
			}

			pubKey := rsa.PublicKey{
				N: new(big.Int).SetBytes(dataout.AuthorizeKeyPublic.Unique.RSA()),
				E: int(dataout.AuthorizeKeyPublic.Params.RSADetail().Exponent)}
			if err := rsa.VerifyPSS(&pubKey, dataout.AuthorizeKeyPublic.NameAlg.GetHash(), h.Sum(nil), sig,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("Invalid auth key")
			}

			keyName, err := dataout.AuthorizeKeyPublic.Name()
			if err != nil {
				t.Errorf("Failed to compute name from auth key public area: %v", err)
			}

			trial, _ := tpm2.ComputeAuthPolicy(data.alg)
			trial.PolicyAuthorize(nil, keyName)
			trial.PolicySecret(pinName, nil)
			trial.PolicyNV(lockName, nil, 0, tpm2.OpEq)

			if !bytes.Equal(trial.GetDigest(), policy) {
				t.Errorf("Unexpected policy digest")
			}
		})
	}
}

func TestComputeDynamicPolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	revokeIndexPub := &tpm2.NVPublic{
		Index:      testCreationParams.PolicyRevocationHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.MakeNVAttributes(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead, tpm2.NVTypeCounter),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       8}

	digestMatrix := make(map[tpm2.HashAlgorithmId]tpm2.DigestList)

	for _, data := range []string{"foo", "bar", "1234", "ABC"} {
		for _, alg := range []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA512} {
			hasher := alg.NewHash()
			hasher.Write([]byte(data))
			digestMatrix[alg] = append(digestMatrix[alg], hasher.Sum(nil))
		}
	}

	for _, data := range []struct {
		desc   string
		alg    tpm2.HashAlgorithmId
		input  dynamicPolicyComputeParams
		policy tpm2.Digest
	}{
		{
			desc: "Single",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				signAlg:                    tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndexPub:       revokeIndexPub,
				policyRevokeCount:          10,
			},
			policy: tpm2.Digest{0x89, 0x1e, 0x22, 0xa2, 0xab, 0x4c, 0x3e, 0x3d, 0x80, 0xfa, 0x5b, 0x16, 0x90, 0x2f, 0xb2, 0x19, 0xaf, 0xee,
				0x81, 0xb5, 0x85, 0x67, 0xdd, 0x0b, 0x06, 0xf1, 0x20, 0x1d, 0xff, 0x1a, 0x8d, 0x8d},
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.HashAlgorithmSHA1,
			input: dynamicPolicyComputeParams{
				key:                        key,
				signAlg:                    tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][2]},
				policyRevokeIndexPub:       revokeIndexPub,
				policyRevokeCount:          4551,
			},
			policy: tpm2.Digest{0xf1, 0xb6, 0x44, 0x98, 0xba, 0xb5, 0x47, 0x14, 0x1a, 0x8f, 0xd8, 0x29, 0x02, 0xbb, 0x72, 0xd1, 0x00, 0xc1,
				0x20, 0xc6},
		},
		{
			desc: "SHA256SessionWithSHA512PCRs",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				signAlg:                    tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA512,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA512,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][1]},
				policyRevokeIndexPub:       revokeIndexPub,
				policyRevokeCount:          403,
			},
			policy: tpm2.Digest{0x45, 0x98, 0x03, 0xc0, 0x34, 0xdb, 0x89, 0x99, 0x7e, 0x72, 0xe7, 0xdb, 0xad, 0xc8, 0x89, 0xef, 0x55, 0xaf,
				0x2b, 0x73, 0xa7, 0x3e, 0x72, 0x7e, 0x59, 0xc2, 0x17, 0x55, 0x0e, 0x1c, 0x39, 0xa7},
		},
		{
			desc: "MultiplePCRValues",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                    key,
				signAlg:                tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][3],
					digestMatrix[tpm2.HashAlgorithmSHA256][2]},
				policyRevokeIndexPub: revokeIndexPub,
				policyRevokeCount:    5,
			},
			policy: tpm2.Digest{0xc3, 0xa9, 0x69, 0x64, 0xa2, 0x66, 0x3c, 0xd0, 0xa7, 0xa8, 0xc8, 0xad, 0xa7, 0xa8, 0x14, 0x24, 0x37, 0x29,
				0x13, 0x08, 0xcc, 0xe2, 0x3f, 0x4f, 0x30, 0xa1, 0xe6, 0x9b, 0xfa, 0xbb, 0xa4, 0xe7},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, err := computeDynamicPolicy(data.alg, &data.input)
			if err != nil {
				t.Fatalf("computeDynamicPolicy failed; %v", err)
			}
			if dataout.SecureBootPCRAlg != data.input.secureBootPCRAlg {
				t.Errorf("Unexpected secure boot PCR algorithm %v", dataout.SecureBootPCRAlg)
			}
			if dataout.UbuntuBootParamsPCRAlg != data.input.ubuntuBootParamsPCRAlg {
				t.Errorf("Unexpected ubuntu boot params PCR algorithm %v", dataout.UbuntuBootParamsPCRAlg)
			}
			if len(dataout.SecureBootORDigests) != len(data.input.secureBootPCRDigests) {
				t.Errorf("Unexpected number of secure boot OR digests")
			}
			if len(dataout.UbuntuBootParamsORDigests) != len(data.input.ubuntuBootParamsPCRDigests) {
				t.Errorf("Unexpected number of ubuntu boot params OR digests")
			}
			if dataout.PolicyRevokeIndexHandle != data.input.policyRevokeIndexPub.Index {
				t.Errorf("Unexpected policy revocation NV index handle")
			}
			if dataout.PolicyRevokeCount != data.input.policyRevokeCount {
				t.Errorf("Unexpected policy revocation count")
			}

			digestSize := data.alg.Size()
			for _, l := range []tpm2.DigestList{dataout.SecureBootORDigests, dataout.UbuntuBootParamsORDigests} {
				for _, digest := range l {
					if len(digest) != int(digestSize) {
						t.Errorf("Unexpected digest size")
					}
				}
			}

			if !bytes.Equal(data.policy, dataout.AuthorizedPolicy) {
				t.Errorf("Unexpected policy digest returned (got %x, expected %x)", dataout.AuthorizedPolicy, data.policy)
			}

			if dataout.AuthorizedPolicySignature.SigAlg != tpm2.SigSchemeAlgRSAPSS {
				t.Errorf("Unexpected authorized policy signature algorithm")
			}
			if dataout.AuthorizedPolicySignature.Signature.RSAPSS().Hash != data.input.signAlg {
				t.Errorf("Unexpected authorized policy signature digest algorithm")
			}

			h := data.input.signAlg.NewHash()
			h.Write(dataout.AuthorizedPolicy)

			if err := rsa.VerifyPSS(&key.PublicKey, data.input.signAlg.GetHash(), h.Sum(nil),
				[]byte(dataout.AuthorizedPolicySignature.Signature.RSAPSS().Sig),
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("Invalid authorized policy signature: %v", err)
			}
		})
	}
}

func TestLockAccess(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
	}

	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, defaultSessionHashAlgorithm)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	sessionFlushed := false
	defer func() {
		if sessionFlushed {
			return
		}
		flushContext(t, tpm, session)
	}()
	session.SetAttrs(tpm2.AttrContinueSession)

	pinIndexPub, _, err := createPinNvIndex(tpm.TPMContext, testCreationParams.PinHandle, session)
	if err != nil {
		t.Fatalf("createPinNvIndex failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
		if err != nil {
			t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	staticPolicyData, key, policy, err :=
		computeStaticPolicy(tpm2.HashAlgorithmSHA256, &staticPolicyComputeParams{pinIndexPub: pinIndexPub, lockIndexName: lockIndex.Name()})
	if err != nil {
		t.Fatalf("computeStaticPolicy failed: %v", err)
	}

	policyRevokeIndexPub, err := createPolicyRevocationNvIndex(tpm.TPMContext, testCreationParams.PolicyRevocationHandle, key, session)
	if err != nil {
		t.Fatalf("createPolicyRevocationNvIndex failed: %v", err)
	}
	policyRevokeIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(policyRevokeIndexPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer func() {
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), policyRevokeIndex, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	event := []byte("foo")
	h := crypto.SHA256.New()
	h.Write(event)
	eventDigest := h.Sum(nil)

	h = crypto.SHA256.New()
	h.Write(make([]byte, crypto.SHA256.Size()))
	h.Write(eventDigest)
	pcrDigest := h.Sum(nil)

	var policyRevokeCount uint64
	if c, err := tpm.NVReadCounter(policyRevokeIndex, policyRevokeIndex, nil); err != nil {
		t.Fatalf("NVReadCounter failed: %v", err)
	} else {
		policyRevokeCount = c
	}

	dynamicPolicyParams := dynamicPolicyComputeParams{
		key:                        key,
		signAlg:                    tpm2.HashAlgorithmSHA256,
		secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
		ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
		secureBootPCRDigests:       tpm2.DigestList{pcrDigest},
		ubuntuBootParamsPCRDigests: tpm2.DigestList{pcrDigest},
		policyRevokeIndexPub:       policyRevokeIndexPub,
		policyRevokeCount:          policyRevokeCount}

	dynamicPolicyData, err := computeDynamicPolicy(tpm2.HashAlgorithmSHA256, &dynamicPolicyParams)
	if err != nil {
		t.Fatalf("computeDynamicPolicy failed: %v", err)
	}

	flushContext(t, tpm, session)
	sessionFlushed = true

	for i := 0; i < 2; i++ {
		func() {
			resetTPMSimulator(t, tpm, tcti)

			for _, p := range []int{secureBootPCR, ubuntuBootParamsPCR} {
				if _, err := tpm.PCREvent(tpm.PCRHandleContext(p), event, nil); err != nil {
					t.Fatalf("PCREvent failed: %v", err)
				}
			}

			sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, defaultSessionHashAlgorithm)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			sessionContext.SetAttrs(tpm2.AttrContinueSession)
			defer flushContext(t, tpm, sessionContext)

			policySessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, policySessionContext)

			err = executePolicySession(tpm, policySessionContext, staticPolicyData, dynamicPolicyData, "")
			if err != nil {
				t.Errorf("executePolicySession failed: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(policySessionContext)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}

			if err := lockAccessToSealedKeysUntilTPMReset(tpm.TPMContext, sessionContext); err != nil {
				t.Errorf("lockAccessUntilTPMReset failed: %v", err)
			}

			if err := tpm.PolicyRestart(policySessionContext); err != nil {
				t.Errorf("PolicyRestart failed: %v", err)
			}

			err = executePolicySession(tpm, policySessionContext, staticPolicyData, dynamicPolicyData, "")
			if err == nil {
				t.Fatalf("executePolicySession should have failed")
			}
			if err.Error() != "policy lock check failed: TPM returned an error whilst executing command TPM_CC_PolicyNV: TPM_RC_NV_LOCKED (NV access locked)" {
				t.Errorf("executePolicySession failed with an unexpected error: %v", err)
			}

			digest, err = tpm.PolicyGetDigest(policySessionContext)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}
		}()
	}
}

func TestExecutePolicy(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, defaultSessionHashAlgorithm)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	sessionFlushed := false
	defer func() {
		if sessionFlushed {
			return
		}
		flushContext(t, tpm, session)
	}()
	session.SetAttrs(tpm2.AttrContinueSession)

	pinIndexPub, pinIndexKeyName, err := createPinNvIndex(tpm.TPMContext, testCreationParams.PinHandle, session)
	if err != nil {
		t.Fatalf("createPinNvIndex failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
		if err != nil {
			t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	policyRevokeIndexPub, err := createPolicyRevocationNvIndex(tpm.TPMContext, testCreationParams.PolicyRevocationHandle, key, session)
	if err != nil {
		t.Fatalf("createPolicyRevocationNvIndex failed: %v", err)
	}
	policyRevokeIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(policyRevokeIndexPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer func() {
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), policyRevokeIndex, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()
	flushContext(t, tpm, session)
	sessionFlushed = true

	var policyRevokeCount uint64
	if c, err := tpm.NVReadCounter(policyRevokeIndex, policyRevokeIndex, nil); err != nil {
		t.Fatalf("NVReadCounter failed: %v", err)
	} else {
		policyRevokeCount = c
	}

	digestMatrix := make(map[tpm2.HashAlgorithmId]tpm2.DigestList)
	for _, data := range []string{"foo", "bar", "xyz", "1234", "5678"} {
		for _, alg := range []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1} {
			hasher := alg.NewHash()
			hasher.Write([]byte(data))
			dataDigest := hasher.Sum(nil)

			digestSize := alg.Size()

			hasher = alg.NewHash()
			hasher.Write(make([]byte, digestSize))
			hasher.Write(dataDigest)

			digestMatrix[alg] = append(digestMatrix[alg], hasher.Sum(nil))
		}
	}

	type pcrEvent struct {
		index int
		data  string
	}

	for _, data := range []struct {
		desc        string
		alg         tpm2.HashAlgorithmId
		input       dynamicPolicyComputeParams
		pcrEvents   []pcrEvent
		pinDefine   string
		pinInput    string
		policyMatch bool
	}{
		{
			desc: "Single",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndexPub:       policyRevokeIndexPub,
				policyRevokeCount:          policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "SHA1SessionWithSHA256PCRs",
			alg:  tpm2.HashAlgorithmSHA1,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndexPub:       policyRevokeIndexPub,
				policyRevokeCount:          policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.HashAlgorithmSHA1,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA1,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA1,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA1][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA1][1]},
				policyRevokeIndexPub:       policyRevokeIndexPub,
				policyRevokeCount:          policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "WithPIN",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndexPub:       policyRevokeIndexPub,
				policyRevokeCount:          policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			pinDefine:   "1234",
			pinInput:    "1234",
			policyMatch: true,
		},
		{
			desc: "WithIncorrectPIN",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndexPub:       policyRevokeIndexPub,
				policyRevokeCount:          policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			pinDefine:   "1234",
			pinInput:    "12345",
			policyMatch: true,
		},
		{
			desc: "NoMatch",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndexPub: policyRevokeIndexPub,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "abc",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: false,
		},
		{
			desc: "MultiplePCRValues1",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyRevokeIndexPub: policyRevokeIndexPub,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "MultiplePCRValues2",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyRevokeIndexPub: policyRevokeIndexPub,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "1234",
				},
			},
			policyMatch: true,
		},
		{
			desc: "MultiplePCRValuesNoMatch",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyRevokeIndexPub: policyRevokeIndexPub,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "bar",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "1234",
				},
			},
			policyMatch: false,
		},
		{
			desc: "RevokedPolicy",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndexPub:       policyRevokeIndexPub,
				policyRevokeCount:          policyRevokeCount - 1,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			resetTPMSimulator(t, tpm, tcti)

			lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
			if err != nil {
				t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
			}

			staticPolicyData, key, policy, err := computeStaticPolicy(data.alg, &staticPolicyComputeParams{pinIndexPub: pinIndexPub, lockIndexName: lockIndex.Name()})
			if err != nil {
				t.Fatalf("computeStaticPolicy failed: %v", err)
			}
			data.input.key = key
			data.input.signAlg = staticPolicyData.AuthorizeKeyPublic.NameAlg
			dynamicPolicyData, err := computeDynamicPolicy(data.alg, &data.input)
			if err != nil {
				t.Fatalf("computeDynamicPolicy failed: %v", err)
			}

			for _, event := range data.pcrEvents {
				if _, err := tpm.PCREvent(tpm.PCRHandleContext(event.index), []byte(event.data), nil); err != nil {
					t.Fatalf("PCREvent failed: %v", err)
				}
			}

			if data.pinDefine != "" {
				pinIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
				if err != nil {
					t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
				}
				if err := performPINChange(tpm, pinIndex, pinIndexKeyName, data.pinDefine); err != nil {
					t.Fatalf("performPINChange failed: %v", err)
				}
				defer func() {
					pinIndex.SetAuthValue([]byte(data.pinDefine))
					if err := performPINChange(tpm, pinIndex, pinIndexKeyName, ""); err != nil {
						t.Errorf("Resetting PIN failed: %v", err)
					}
				}()
			}

			session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, session)

			err = executePolicySession(tpm, session, staticPolicyData, dynamicPolicyData, data.pinInput)
			if data.input.policyRevokeCount < policyRevokeCount {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMError
				if !xerrors.As(err, &e) || e.Code != tpm2.ErrorPolicy || e.Command != tpm2.CommandPolicyNV {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if !data.policyMatch {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMParameterError
				if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorValue || e.Command() != tpm2.CommandPolicyOR || e.Index != 1 {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if data.pinInput != data.pinDefine {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMSessionError
				if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorAuthFail || e.Command() != tpm2.CommandPolicySecret {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if err != nil {
				t.Errorf("Failed to execute policy session: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(session)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			match := bytes.Equal(digest, policy)
			if data.policyMatch && data.pinInput == data.pinDefine &&
				data.input.policyRevokeCount >= policyRevokeCount {
				if !match {
					t.Errorf("Session digest didn't match policy digest")
				}
			} else if match {
				t.Errorf("Session digest shouldn't match policy digest")
			}
		})
	}
}
