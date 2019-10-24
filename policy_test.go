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

func TestComputePolicy(t *testing.T) {
	hasher := hashAlgToGoHash(tpm2.AlgorithmSHA256)
	hasher.Write([]byte("PIN"))
	pinName, _ := tpm2.MarshalToBytes(tpm2.AlgorithmSHA256, tpm2.RawBytes(hasher.Sum(nil)))
	pinIndex := &mockResourceContext{pinName, testCreationParams.PinHandle}

	hasher = hashAlgToGoHash(tpm2.AlgorithmSHA256)
	hasher.Write([]byte("REVOKE"))
	revokeIndexName, _ := tpm2.MarshalToBytes(tpm2.AlgorithmSHA256, tpm2.RawBytes(hasher.Sum(nil)))
	revokeIndex := &mockResourceContext{revokeIndexName, testCreationParams.PolicyRevocationHandle}

	digestMatrix := make(map[tpm2.AlgorithmId]tpm2.DigestList)

	for _, data := range []string{"foo", "bar", "1234", "ABC"} {
		for _, alg := range []tpm2.AlgorithmId{tpm2.AlgorithmSHA256, tpm2.AlgorithmSHA512} {
			hasher := hashAlgToGoHash(alg)
			hasher.Write([]byte(data))
			digestMatrix[alg] = append(digestMatrix[alg], hasher.Sum(nil))
		}
	}

	for _, data := range []struct {
		desc   string
		alg    tpm2.AlgorithmId
		input  policyComputeInput
		output tpm2.Digest
	}{
		{
			desc: "Single",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA256,
				grubPCRAlg:           tpm2.AlgorithmSHA256,
				snapModelPCRAlg:      tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    revokeIndex,
				policyRevokeCount:    10,
			},
			output: tpm2.Digest{0xa8, 0x14, 0x47, 0x66, 0x4c, 0xbb, 0x32, 0x61, 0x8c, 0x9b, 0x31, 0xfa,
				0xd6, 0x20, 0xdb, 0xff, 0xba, 0x66, 0x37, 0xdc, 0xbf, 0x85, 0x4e, 0x19, 0xac, 0xf5,
				0xf8, 0xb4, 0x14, 0x99, 0xb8, 0x52},
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA256,
				grubPCRAlg:           tpm2.AlgorithmSHA256,
				snapModelPCRAlg:      tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinObjectName:        pinName,
				pinIndex:             pinIndex,
				policyRevokeIndex:    revokeIndex,
				policyRevokeCount:    4551,
			},
			output: tpm2.Digest{0xf1, 0xe0, 0xaa, 0x57, 0xfc, 0x19, 0x03, 0x86, 0x9a, 0x43, 0xca, 0x5a,
				0x3a, 0x56, 0xb8, 0x48, 0xe7, 0x7f, 0xe7, 0xc7},
		},
		{
			desc: "SHA256SessionWithSHA512PCRs",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA512,
				grubPCRAlg:           tpm2.AlgorithmSHA512,
				snapModelPCRAlg:      tpm2.AlgorithmSHA512,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA512][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA512][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA512][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    revokeIndex,
				policyRevokeCount:    403,
			},
			output: tpm2.Digest{0x77, 0x9b, 0x50, 0x0a, 0x46, 0x37, 0x26, 0x3b, 0xbb, 0xde, 0xa6, 0xe4,
				0x0d, 0xd1, 0x69, 0x94, 0x7d, 0x2c, 0x4c, 0xff, 0x72, 0xbc, 0x8e, 0xad, 0xf4, 0x86,
				0x3b, 0x9c, 0xfb, 0x6a, 0x93, 0x69},
		},
		{
			desc: "MultiplePCRValues",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg: tpm2.AlgorithmSHA256,
				grubPCRAlg:       tpm2.AlgorithmSHA256,
				snapModelPCRAlg:  tpm2.AlgorithmSHA512,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][0],
					digestMatrix[tpm2.AlgorithmSHA256][1]},
				grubPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][3],
					digestMatrix[tpm2.AlgorithmSHA256][2]},
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA512][2]},
				pinIndex:            pinIndex,
				policyRevokeIndex:   revokeIndex,
				policyRevokeCount:   5,
			},
			output: tpm2.Digest{0xb7, 0x15, 0xc1, 0xad, 0x46, 0x47, 0xd6, 0x1d, 0x73, 0x03, 0xb8, 0x26,
				0xfa, 0x74, 0xc4, 0x72, 0x08, 0x71, 0xc6, 0x83, 0x99, 0x80, 0x4c, 0x9b, 0x4c, 0x89,
				0x03, 0x52, 0x72, 0xed, 0xdc, 0x16},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, policy, err := computePolicy(data.alg, &data.input)
			if err != nil {
				t.Fatalf("computePolicy failed: %v", err)
			}
			if dataout.Algorithm != data.alg {
				t.Errorf("Unexpected session algorithm %v", dataout.Algorithm)
			}
			if dataout.SecureBootPCRAlg != data.input.secureBootPCRAlg {
				t.Errorf("Unexpected secure boot PCR algorithm %v", dataout.SecureBootPCRAlg)
			}
			if dataout.GrubPCRAlg != data.input.grubPCRAlg {
				t.Errorf("Unexpected grub PCR algorithm %v", dataout.GrubPCRAlg)
			}
			if dataout.SnapModelPCRAlg != data.input.snapModelPCRAlg {
				t.Errorf("Unexpected secure snap model PCR algorithm %v", dataout.SnapModelPCRAlg)
			}
			if len(dataout.SecureBootORDigests) != len(data.input.secureBootPCRDigests) {
				t.Errorf("Unexpected number of secure boot OR digests")
			}
			if len(dataout.GrubORDigests) != len(data.input.grubPCRDigests) {
				t.Errorf("Unexpected number of grub OR digests")
			}
			if len(dataout.SnapModelORDigests) != len(data.input.snapModelPCRDigests) {
				t.Errorf("Unexpected number of snap model OR digests")
			}
			if dataout.PolicyRevokeIndexHandle != data.input.policyRevokeIndex.Handle() {
				t.Errorf("Unexpected policy revocation NV index handle")
			}
			if dataout.PolicyRevokeCount != data.input.policyRevokeCount {
				t.Errorf("Unexpected policy revocation count")
			}

			digestSize := getDigestSize(data.alg)
			for _, l := range []tpm2.DigestList{dataout.SecureBootORDigests,
				dataout.GrubORDigests, dataout.SnapModelORDigests} {
				for _, digest := range l {
					if len(digest) != int(digestSize) {
						t.Errorf("Unexpected digest size")
					}
				}
			}

			if !bytes.Equal(data.output, policy) {
				t.Errorf("Unexpected policy digest returned (got %x, expected %x)", policy,
					data.output)
			}
		})
	}
}

func TestExecutePolicy(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	pinIndex, pinPolicies, err := createPinNvIndex(tpm, testCreationParams.PinHandle, nil)
	if err != nil {
		t.Fatalf("createPinNvIndex failed: %v", err)
	}
	defer func() {
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, pinIndex, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	policyRevokeIndex, err := createPolicyRevocationNvIndex(tpm, testCreationParams.PolicyRevocationHandle, nil)
	if err != nil {
		t.Fatalf("createPolicyRevocationNvIndex failed: %v", err)
	}
	defer func() {
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, policyRevokeIndex, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	var policyRevokeCount uint64
	if c, err := tpm.NVReadCounter(policyRevokeIndex, policyRevokeIndex, nil); err != nil {
		t.Fatalf("NVReadCounter failed: %v", err)
	} else {
		policyRevokeCount = c
	}

	digestMatrix := make(map[tpm2.AlgorithmId]tpm2.DigestList)
	for _, data := range []string{"foo", "bar", "xyz", "1234", "5678"} {
		for _, alg := range []tpm2.AlgorithmId{tpm2.AlgorithmSHA256, tpm2.AlgorithmSHA1} {
			hasher := hashAlgToGoHash(alg)
			hasher.Write([]byte(data))
			dataDigest := hasher.Sum(nil)

			digestSize := getDigestSize(alg)

			hasher = hashAlgToGoHash(alg)
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
		alg         tpm2.AlgorithmId
		input       policyComputeInput
		pcrEvents   []pcrEvent
		pinDefine   string
		pinInput    string
		policyMatch bool
	}{
		{
			desc: "Single",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA256,
				grubPCRAlg:           tpm2.AlgorithmSHA256,
				snapModelPCRAlg:      tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    policyRevokeIndex,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: true,
		},
		{
			desc: "SHA1SessionWithSHA256PCRs",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA256,
				grubPCRAlg:           tpm2.AlgorithmSHA256,
				snapModelPCRAlg:      tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    policyRevokeIndex,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: true,
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA1,
				grubPCRAlg:           tpm2.AlgorithmSHA1,
				snapModelPCRAlg:      tpm2.AlgorithmSHA1,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA1][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA1][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA1][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    policyRevokeIndex,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: true,
		},
		{
			desc: "WithPIN",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA256,
				grubPCRAlg:           tpm2.AlgorithmSHA256,
				snapModelPCRAlg:      tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    policyRevokeIndex,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			pinDefine:   "1234",
			pinInput:    "1234",
			policyMatch: true,
		},
		{
			desc: "WithIncorrectPIN",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA256,
				grubPCRAlg:           tpm2.AlgorithmSHA256,
				snapModelPCRAlg:      tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    policyRevokeIndex,
				policyRevokeCount:    policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			pinDefine:   "1234",
			pinInput:    "12345",
			policyMatch: true,
		},
		{
			desc: "NoMatch",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg: tpm2.AlgorithmSHA256,
				grubPCRAlg:       tpm2.AlgorithmSHA256,
				snapModelPCRAlg:  tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:            pinIndex,
				policyRevokeIndex:   policyRevokeIndex,
				policyRevokeCount:   policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "abc",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: false,
		},
		{
			desc: "MultiplePCRValues1",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg: tpm2.AlgorithmSHA256,
				grubPCRAlg:       tpm2.AlgorithmSHA256,
				snapModelPCRAlg:  tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][0],
					digestMatrix[tpm2.AlgorithmSHA256][4]},
				grubPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][1],
					digestMatrix[tpm2.AlgorithmSHA256][3]},
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:            pinIndex,
				policyRevokeIndex:   policyRevokeIndex,
				policyRevokeCount:   policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: true,
		},
		{
			desc: "MultiplePCRValues2",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg: tpm2.AlgorithmSHA256,
				grubPCRAlg:       tpm2.AlgorithmSHA256,
				snapModelPCRAlg:  tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][0],
					digestMatrix[tpm2.AlgorithmSHA256][4]},
				grubPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][1],
					digestMatrix[tpm2.AlgorithmSHA256][3]},
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:            pinIndex,
				policyRevokeIndex:   policyRevokeIndex,
				policyRevokeCount:   policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "1234",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: true,
		},
		{
			desc: "MultiplePCRValuesNoMatch",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg: tpm2.AlgorithmSHA256,
				grubPCRAlg:       tpm2.AlgorithmSHA256,
				snapModelPCRAlg:  tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][0],
					digestMatrix[tpm2.AlgorithmSHA256][4]},
				grubPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][1],
					digestMatrix[tpm2.AlgorithmSHA256][3]},
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:            pinIndex,
				policyRevokeIndex:   policyRevokeIndex,
				policyRevokeCount:   policyRevokeCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "bar",
				},
				{
					index: grubPCR,
					data:  "1234",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: false,
		},
		{
			desc: "RevokedPolicy",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:     tpm2.AlgorithmSHA256,
				grubPCRAlg:           tpm2.AlgorithmSHA256,
				snapModelPCRAlg:      tpm2.AlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][0]},
				grubPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][1]},
				snapModelPCRDigests:  tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinIndex:             pinIndex,
				policyRevokeIndex:    policyRevokeIndex,
				policyRevokeCount:    policyRevokeCount - 1,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "xyz",
				},
			},
			policyMatch: true,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			resetTPMSimulator(t, tpm, tcti)

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
				if err := performPINChange(tpm, pinIndex.Handle(), pinPolicies, "",
					data.pinDefine); err != nil {
					t.Fatalf("performPINChange failed: %v", err)
				}
				defer func() {
					if err := performPINChange(tpm, pinIndex.Handle(), pinPolicies,
						data.pinDefine, ""); err != nil {
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

			err = executePolicySession(tpm, sessionContext, policyData, data.pinInput)
			if data.input.policyRevokeCount < policyRevokeCount {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMError
				if !xerrors.As(err, &e) || e.Code != tpm2.ErrorPolicy || e.Command != tpm2.CommandPolicyNV {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if data.pinInput != data.pinDefine {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMSessionError
				if !xerrors.As(err, &e) || e.Code != tpm2.ErrorAuthFail || e.Command != tpm2.CommandPolicySecret {
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
