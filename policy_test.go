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
	h := pinNvIndexNameAlgorithm.NewHash()
	h.Write([]byte("PIN"))
	pinName, _ := tpm2.MarshalToBytes(tpm2.HashAlgorithmSHA256, tpm2.RawBytes(h.Sum(nil)))
	pinIndex := &mockResourceContext{pinName, testCreationParams.PinHandle}

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
			dataout, key, policy, err := computeStaticPolicy(data.alg, &staticPolicyComputeInput{pinIndex: pinIndex})
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

			h := signingKeyNameAlgorithm.NewHash()
			h.Write(make(tpm2.Digest, data.alg.Size()))

			sig, err := rsa.SignPSS(rand.Reader, key, signingKeyNameAlgorithm.GetHash(), h.Sum(nil),
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Errorf("SignPSS failed: %v", err)
			}

			pubKey := rsa.PublicKey{
				N: new(big.Int).SetBytes(dataout.AuthorizeKeyPublic.Unique.RSA()),
				E: int(dataout.AuthorizeKeyPublic.Params.RSADetail().Exponent)}
			if err := rsa.VerifyPSS(&pubKey, signingKeyNameAlgorithm.GetHash(), h.Sum(nil), sig,
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

	h := tpm2.HashAlgorithmSHA256.NewHash()
	h.Write([]byte("REVOKE"))
	revokeIndexName, _ := tpm2.MarshalToBytes(tpm2.HashAlgorithmSHA256, tpm2.RawBytes(h.Sum(nil)))
	revokeIndex := &mockResourceContext{revokeIndexName, testCreationParams.PolicyRevocationHandle}

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
		input  dynamicPolicyComputeInput
		policy tpm2.Digest
	}{
		{
			desc: "Single",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeInput{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeIndex:          revokeIndex,
				policyRevokeCount:          10,
			},
			policy: tpm2.Digest{0xd0, 0xe4, 0xba, 0x2f, 0xbc, 0xc6, 0xf0, 0xd5, 0x84, 0xc2, 0xeb, 0xdf, 0xa6, 0x8d, 0x6b, 0xa3, 0x6a, 0x3b,
				0xf4, 0xbf, 0x51, 0x4a, 0x16, 0x5a, 0xef, 0xfd, 0x62, 0x77, 0x7d, 0x53, 0xb3, 0xff},
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.HashAlgorithmSHA1,
			input: dynamicPolicyComputeInput{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][2]},
				policyRevokeIndex:          revokeIndex,
				policyRevokeCount:          4551,
			},
			policy: tpm2.Digest{0xd6, 0xe3, 0xfa, 0xd2, 0xc2, 0xfa, 0x72, 0x4f, 0x22, 0x67, 0xf6, 0x1d, 0x96, 0xea, 0x53, 0x6b, 0xf5, 0xe1,
				0xc7, 0x50},
		},
		{
			desc: "SHA256SessionWithSHA512PCRs",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeInput{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA512,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA512,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][1]},
				policyRevokeIndex:          revokeIndex,
				policyRevokeCount:          403,
			},
			policy: tpm2.Digest{0x3e, 0x43, 0x91, 0x11, 0xfd, 0x5c, 0xb6, 0xbb, 0x00, 0x41, 0x93, 0xec, 0xd4, 0xc1, 0xc6, 0x5e, 0x5b, 0x09,
				0x0b, 0x22, 0xeb, 0xe5, 0x71, 0x67, 0x86, 0x6d, 0xf5, 0xe5, 0x1f, 0x1c, 0x6d, 0x62},
		},
		{
			desc: "MultiplePCRValues",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeInput{
				key:                    key,
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][3],
					digestMatrix[tpm2.HashAlgorithmSHA256][2]},
				policyRevokeIndex: revokeIndex,
				policyRevokeCount: 5,
			},
			policy: tpm2.Digest{0xd3, 0x65, 0x88, 0x91, 0xd4, 0x93, 0x8a, 0x49, 0x3c, 0xbb, 0xe0, 0x7f, 0xc7, 0x5e, 0x94, 0x16, 0x65, 0x04,
				0x74, 0xff, 0xd9, 0xfa, 0xab, 0xab, 0xa9, 0xcf, 0x5f, 0xcf, 0xa6, 0x45, 0x6e, 0xbb},
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
			if dataout.PolicyRevokeIndexHandle != data.input.policyRevokeIndex.Handle() {
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
			if dataout.AuthorizedPolicySignature.Signature.RSAPSS().Hash != signingKeyNameAlgorithm {
				t.Errorf("Unexpected authorized policy signature digest algorithm")
			}

			h := signingKeyNameAlgorithm.NewHash()
			h.Write(dataout.AuthorizedPolicy)

			if err := rsa.VerifyPSS(&key.PublicKey, signingKeyNameAlgorithm.GetHash(), h.Sum(nil),
				[]byte(dataout.AuthorizedPolicySignature.Signature.RSAPSS().Sig),
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("Invalid authorized policy signature: %v", err)
			}
		})
	}
}

func TestExecutePolicy(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, defaultHashAlgorithm, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	sessionFlushed := false
	defer func() {
		if sessionFlushed {
			return
		}
		flushContext(t, tpm, sessionContext)
	}()

	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrContinueSession}

	_, err = createPinNvIndex(tpm.TPMContext, testCreationParams.PinHandle, nil, &session)
	if err != nil {
		t.Fatalf("createPinNvIndex failed: %v", err)
	}
	defer func() {
		context, err := tpm.WrapHandle(testCreationParams.PinHandle)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, context, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	policyRevokeIndex, err := createPolicyRevocationNvIndex(tpm.TPMContext, testCreationParams.PolicyRevocationHandle, nil, &session)
	if err != nil {
		t.Fatalf("createPolicyRevocationNvIndex failed: %v", err)
	}
	defer func() {
		context, err := tpm.WrapHandle(testCreationParams.PolicyRevocationHandle)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, context, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()
	flushContext(t, tpm, sessionContext)
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
		input       policyComputeInput
		pcrEvents   []pcrEvent
		pinDefine   string
		pinInput    string
		policyMatch bool
	}{
		{
			desc: "Single",
			alg:  tpm2.HashAlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
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
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
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
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA1,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA1,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA1][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA1][1]},
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
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
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
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
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
			input: policyComputeInput{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyRevokeCount: policyRevokeCount,
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
			input: policyComputeInput{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyRevokeCount: policyRevokeCount,
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
			input: policyComputeInput{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyRevokeCount: policyRevokeCount,
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
			input: policyComputeInput{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyRevokeCount: policyRevokeCount,
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
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
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
			pinIndex, err := tpm.WrapHandle(testCreationParams.PinHandle)
			if err != nil {
				t.Fatalf("WrapHandle failed: %v", err)
			}
			policyRevokeIndex, err := tpm.WrapHandle(testCreationParams.PolicyRevocationHandle)
			if err != nil {
				t.Fatalf("WrapHandle failed: %v", err)
			}
			data.input.pinIndex = pinIndex
			data.input.policyRevokeIndex = policyRevokeIndex

			policyData, policy, err := computePolicy(data.alg, &data.input)
			if err != nil {
				t.Fatalf("computePolicy failed: %v", err)
			}

			for _, event := range data.pcrEvents {
				if _, err := tpm.PCREvent(tpm2.Handle(event.index),
					[]byte(event.data), nil); err != nil {
					t.Fatalf("PCREvent failed: %v", err)
				}
			}

			if data.pinDefine != "" {
				if err := performPINChange(tpm, pinIndex.Handle(), "", data.pinDefine); err != nil {
					t.Fatalf("performPINChange failed: %v", err)
				}
				defer func() {
					if err := performPINChange(tpm, pinIndex.Handle(), data.pinDefine, ""); err != nil {
						t.Errorf("Resetting PIN failed: %v", err)
					}
				}()
			}

			sessionContext, err :=
				tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			err = executePolicySession(tpm, sessionContext, policyData.Static, policyData.Dynamic, data.pinInput)
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

			digest, err := tpm.PolicyGetDigest(sessionContext)
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
