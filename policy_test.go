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
	pinName, _ := tpm2.MarshalToBytes(tpm2.AlgorithmSHA256, tpm2.RawBytes(hasher.Sum(nil)))

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
				pinObjectName:        pinName,
			},
			output: tpm2.Digest{0x7c, 0x53, 0x87, 0x2b, 0x7f, 0x16, 0x47, 0xdb, 0x80, 0x46, 0x83, 0x6e,
				0x25, 0xc3, 0xa6, 0x66, 0x42, 0x1b, 0x9b, 0x9b, 0x98, 0xe9, 0x5b, 0x14, 0x8d, 0x63,
				0xc4, 0x5d, 0x56, 0xa8, 0xc3, 0x5e},
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
			},
			output: tpm2.Digest{0x93, 0x21, 0x88, 0x6a, 0xbf, 0xbf, 0xa5, 0x1a, 0x90, 0x13, 0x9a, 0x47,
				0xb9, 0x43, 0xdf, 0x09, 0xed, 0xed, 0x9e, 0x19},
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
				pinObjectName:        pinName,
			},
			output: tpm2.Digest{0xa4, 0x6f, 0x82, 0x03, 0xc3, 0x32, 0x8b, 0xab, 0x22, 0x81, 0xcc, 0xc3,
				0x4a, 0x08, 0x9f, 0x9b, 0x9c, 0x23, 0xa2, 0xfc, 0xe3, 0x06, 0xaf, 0xbe, 0xf4, 0x4b,
				0x3f, 0x1a, 0x85, 0xae, 0xc7, 0x00},
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
				pinObjectName:       pinName,
			},
			output: tpm2.Digest{0x6c, 0xa6, 0x19, 0x30, 0x5b, 0x63, 0x1a, 0xaa, 0xc9, 0x14, 0x47, 0x1d,
				0x49, 0xbe, 0x49, 0x21, 0xa6, 0x8d, 0x85, 0xde, 0xe8, 0xfb, 0x36, 0xcc, 0xaa, 0xe3,
				0x16, 0x7c, 0x61, 0x10, 0xf7, 0x79},
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
				pinObjectName:        pinName,
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
				pinObjectName:        pinName,
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
				pinObjectName:        pinName,
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
				pinObjectName:        pinName,
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
				pinObjectName:        pinName,
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
				pinObjectName:       pinName,
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
				pinObjectName:       pinName,
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
				pinObjectName:       pinName,
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
				pinObjectName:       pinName,
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
			if data.pinInput != data.pinDefine {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				if err != policySecretAuthFailError {
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
			if data.policyMatch && data.pinInput == data.pinDefine {
				if !match {
					t.Errorf("Session digest didn't match policy digest")
				}
			} else if match {
				t.Errorf("Session digest shouldn't match policy digest")
			}
		})
	}
}
