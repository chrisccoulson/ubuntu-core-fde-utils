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
)

func TestComputePolicy(t *testing.T) {
	hasher := hashAlgToGoHash(tpm2.AlgorithmSHA256)
	hasher.Write([]byte("PIN"))
	pinName, _ := tpm2.MarshalToBytes(tpm2.AlgorithmSHA256, tpm2.RawSlice(hasher.Sum(nil)))

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
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0x89, 0x01, 0x95, 0xd3, 0x1c, 0xf2, 0xfa, 0x32, 0x8c, 0x7d, 0xe2, 0xa4,
				0xcb, 0x32, 0xe6, 0xd3, 0x3e, 0x0a, 0x6a, 0x21, 0x07, 0x20, 0xfe, 0xf5, 0x8e, 0x43,
				0xd2, 0x07, 0x0f, 0x89, 0x2c, 0x8f},
		},
		{
			desc: "SingleSHA1Session",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0x44, 0x63, 0x4f, 0xdf, 0xf1, 0x9b, 0xd1, 0xe6, 0x3c, 0x09, 0xd0, 0x8e,
				0x46, 0x7a, 0xec, 0xf7, 0x99, 0x17, 0x78, 0x08},
		},
		{
			desc: "SingleSHA256SessionWithSHA512PCRs",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA512,
						grubPCRAlg:       tpm2.AlgorithmSHA512,
						snapModelPCRAlg:  tpm2.AlgorithmSHA512,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA512][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA512][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA512][2]},
					},
				},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0x47, 0x62, 0x25, 0x9f, 0x13, 0x69, 0xef, 0xe7, 0xa6, 0x6e, 0x6b, 0xd5,
				0x13, 0x0c, 0xd9, 0xd2, 0xe4, 0x77, 0xed, 0x23, 0x1c, 0x83, 0x56, 0xfd, 0x34, 0x8a,
				0x98, 0xe4, 0xb6, 0x57, 0x7f, 0xdd},
		},
		{
			desc: "SingleSubPolicyWithMultiplePCRValues",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA512,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0],
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3],
							digestMatrix[tpm2.AlgorithmSHA256][2]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA512][2]},
					},
				},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0x39, 0xbd, 0xf1, 0x05, 0x85, 0xb1, 0xb5, 0xdb, 0xcd, 0xef, 0xfa, 0x3d,
				0x45, 0xbd, 0x24, 0xe3, 0x81, 0x95, 0x16, 0x79, 0xf1, 0x9a, 0xc4, 0xa6, 0x56, 0x60,
				0xdc, 0xba, 0xf2, 0x6b, 0xe8, 0x13},
		},
		{
			desc: "MultipleSubPolicies",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1],
							digestMatrix[tpm2.AlgorithmSHA256][2]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2],
							digestMatrix[tpm2.AlgorithmSHA256][3]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0xd2, 0x98, 0x16, 0x82, 0xe2, 0xce, 0x97, 0x32, 0x2f, 0x0c, 0xff, 0xbc,
				0xa0, 0x3b, 0xba, 0x48, 0xd8, 0xe1, 0x2a, 0x18, 0x82, 0x94, 0xdd, 0x17, 0x99, 0x36,
				0x33, 0x23, 0x03, 0x5d, 0x2f, 0xdb},
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
			if len(dataout.SubPolicyORDigests) != len(data.input.subPolicies) {
				t.Errorf("Unexpected number of sub policy OR digests")
			}
			if len(dataout.SubPolicyData) != len(data.input.subPolicies) {
				t.Fatalf("Unexpected number of sub policy data structures")
			}
			for i := 0; i < len(data.input.subPolicies); i++ {
				if dataout.SubPolicyData[i].SecureBootPCRAlg !=
					data.input.subPolicies[i].secureBootPCRAlg {
					t.Errorf("Unexpected secure boot PCR algorithm %v for index %d",
						dataout.SubPolicyData[i].SecureBootPCRAlg, i)
				}
				if dataout.SubPolicyData[i].GrubPCRAlg != data.input.subPolicies[i].grubPCRAlg {
					t.Errorf("Unexpected grub PCR algorithm %v for index %d",
						dataout.SubPolicyData[i].GrubPCRAlg, i)
				}
				if dataout.SubPolicyData[i].SnapModelPCRAlg !=
					data.input.subPolicies[i].snapModelPCRAlg {
					t.Errorf("Unexpected snap model PCR algorithm %v for index %d",
						dataout.SubPolicyData[i].SnapModelPCRAlg, i)
				}
				digestSize, _ := getDigestSize(data.alg)
				for _, l := range []tpm2.DigestList{dataout.SubPolicyData[i].SecureBootORDigests,
					dataout.SubPolicyData[i].GrubORDigests,
					dataout.SubPolicyData[i].SnapModelORDigests} {
					for _, digest := range l {
						if len(digest) != int(digestSize) {
							t.Errorf("Unexpected digest size")
						}
					}
				}
				for _, digest := range dataout.SubPolicyORDigests {
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

	if err := ProvisionTPM(tpm, nil); err != nil && err != ErrClearRequiresPPI {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	status, err := ProvisionStatus(tpm)
	if err != nil {
		t.Fatalf("Cannot check provision status: %v", err)
	}
	if status&AttrValidSRK == 0 {
		t.Fatalf("No valid SRK for test")
	}

	pinPriv, pinPub, err := createPINObject(tpm)
	if err != nil {
		t.Fatalf("Failed to create PIN object: %v", err)
	}
	pinName, _ := pinPub.Name()

	digestMatrix := make(map[tpm2.AlgorithmId]tpm2.DigestList)
	for _, data := range []string{"foo", "bar", "xyz", "1234", "5678"} {
		for _, alg := range []tpm2.AlgorithmId{tpm2.AlgorithmSHA256, tpm2.AlgorithmSHA1} {
			hasher := hashAlgToGoHash(alg)
			hasher.Write([]byte(data))
			dataDigest := hasher.Sum(nil)

			digestSize, _ := getDigestSize(alg)

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
		desc      string
		alg       tpm2.AlgorithmId
		input     policyComputeInput
		pcrEvents []pcrEvent
		pinDefine string
		pinInput  string
		errMsg    string
		match     bool
	}{
		{
			desc: "Single",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
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
			match: true,
		},
		{
			desc: "SingleSHA1SessionWithSHA256PCRs",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
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
			match: true,
		},
		{
			desc: "SingleSHA1Session",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA1,
						grubPCRAlg:       tpm2.AlgorithmSHA1,
						snapModelPCRAlg:  tpm2.AlgorithmSHA1,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA1][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA1][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA1][2]},
					},
				},
				pinObjectName: pinName,
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
			match: true,
		},
		{
			desc: "SingleWithPIN",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
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
			pinDefine: "1234",
			pinInput:  "1234",
			match:     true,
		},
		{
			desc: "SingleWithIncorrectPIN",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
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
			pinDefine: "1234",
			pinInput:  "12345",
			errMsg: "cannot execute PolicySecret command: TPM returned an error for session 1 " +
				"whilst executing command TPM_CC_PolicySecret: TPM_RC_AUTH_FAIL (the " +
				"authorization HMAC check failed and DA counter incremented)",
			match: false,
		},
		{
			desc: "SingleNoMatch",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
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
			match: false,
		},
		{
			desc: "SingleSubPolicyWithMultiplePCRValues1",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1],
							digestMatrix[tpm2.AlgorithmSHA256][3]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
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
			match: true,
		},
		{
			desc: "SingleSubPolicyWithMultiplePCRValues2",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1],
							digestMatrix[tpm2.AlgorithmSHA256][3]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				pinObjectName: pinName,
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
			match: true,
		},
		{
			desc: "MultipleSubPolicies1",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][4]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
				},
				pinObjectName: pinName,
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
			match: true,
		},
		{
			desc: "MultipleSubPolicies2",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][4]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
				},
				pinObjectName: pinName,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "5678",
				},
				{
					index: grubPCR,
					data:  "bar",
				},
				{
					index: snapModelPCR,
					data:  "1234",
				},
			},
			match: true,
		},
		{
			desc: "MultipleSubPoliciesNoMatch",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						snapModelPCRAlg:  tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][4]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						snapModelPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
				},
				pinObjectName: pinName,
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
					data:  "1234",
				},
			},
			match: false,
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

			srkContext, err := tpm.WrapHandle(srkHandle)
			if err != nil {
				t.Errorf("WrapHandle failed: %v", err)
			}

			pinContext, _, err := tpm.Load(srkContext, pinPriv, pinPub, nil)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			defer flushContext(t, tpm, pinContext)

			if data.pinDefine != "" {
				priv, err := tpm.ObjectChangeAuth(pinContext, srkContext,
					tpm2.Auth(data.pinDefine), nil)
				if err != nil {
					t.Fatalf("ObjectChangeAuth failed: %v", err)
				}
				pinContext, _, err = tpm.Load(srkContext, priv, pinPub, nil)
				if err != nil {
					t.Fatalf("Load failed: %v", err)
				}
				defer flushContext(t, tpm, pinContext)
			}

			sessionContext, err :=
				tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			err = executePolicySession(tpm, sessionContext, pinContext, policyData, data.pinInput)
			if data.errMsg == "" {
				if err != nil {
					t.Errorf("Failed to execute policy session: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				if err.Error() != data.errMsg {
					t.Errorf("Unexpected error message: %v", err)
				}
			}

			digest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			match := bytes.Equal(digest, policy)
			if data.match {
				if !match {
					t.Errorf("Session digest didn't match policy digest")
				}
			} else if match {
				t.Errorf("Session digest shouldn't match policy digest")
			}
		})
	}
}
