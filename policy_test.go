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
	hasher := tpm2.HashAlgorithmSHA256.NewHash()
	hasher.Write([]byte("PIN"))
	pinName, _ := tpm2.MarshalToBytes(tpm2.HashAlgorithmSHA256, tpm2.RawBytes(hasher.Sum(nil)))
	pinIndex := &mockResourceContext{pinName, testCreationParams.PinHandle}

	hasher = tpm2.HashAlgorithmSHA256.NewHash()
	hasher.Write([]byte("REVOKE"))
	revokeIndexName, _ := tpm2.MarshalToBytes(tpm2.HashAlgorithmSHA256, tpm2.RawBytes(hasher.Sum(nil)))
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
		input  policyComputeInput
		output tpm2.Digest
	}{
		{
			desc: "Single",
			alg:  tpm2.HashAlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				pinIndex:                   pinIndex,
				policyRevokeIndex:          revokeIndex,
				policyRevokeCount:          10,
			},
			output: tpm2.Digest{0x02, 0xc6, 0xa7, 0x61, 0xeb, 0x2e, 0xce, 0x14, 0xc5, 0xe1, 0xc5, 0x24, 0x83, 0x0c, 0xa8, 0xc1, 0x70, 0xdc,
				0x30, 0x92, 0xd6, 0x2c, 0x49, 0x48, 0x8e, 0x91, 0x69, 0x4d, 0x6a, 0x79, 0x70, 0xef},
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.HashAlgorithmSHA1,
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				pinIndex:                   pinIndex,
				policyRevokeIndex:          revokeIndex,
				policyRevokeCount:          4551,
			},
			output: tpm2.Digest{0x7b, 0x0d, 0x31, 0x62, 0xda, 0x67, 0x50, 0x08, 0x02, 0xea, 0x1e, 0x70, 0x22, 0x3b, 0x1c, 0x73, 0xf4, 0xd2,
				0x80, 0x07},
		},
		{
			desc: "SHA256SessionWithSHA512PCRs",
			alg:  tpm2.HashAlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA512,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA512,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][1]},
				pinIndex:                   pinIndex,
				policyRevokeIndex:          revokeIndex,
				policyRevokeCount:          403,
			},
			output: tpm2.Digest{0x1e, 0x97, 0xd2, 0x1c, 0xc8, 0xbd, 0x31, 0xc2, 0x63, 0x58, 0xb3, 0x65, 0xc9, 0x2a, 0xae, 0x56, 0x11, 0x36,
				0x91, 0x3c, 0x14, 0x5c, 0x5a, 0x2d, 0xa4, 0x44, 0x0c, 0xc5, 0xd4, 0x70, 0x89, 0xff},
		},
		{
			desc: "MultiplePCRValues",
			alg:  tpm2.HashAlgorithmSHA256,
			input: policyComputeInput{
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][3],
					digestMatrix[tpm2.HashAlgorithmSHA256][2]},
				pinIndex:          pinIndex,
				policyRevokeIndex: revokeIndex,
				policyRevokeCount: 5,
			},
			output: tpm2.Digest{0x99, 0x66, 0x62, 0x60, 0x64, 0x25, 0xe0, 0x89, 0x98, 0xae, 0xcf, 0x07, 0x4c, 0xc0, 0x48, 0x46, 0x5a, 0x25,
				0x33, 0x95, 0x1d, 0xd5, 0x28, 0x89, 0xb2, 0xd6, 0x30, 0xd4, 0xb5, 0x32, 0xe4, 0x87},
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
			if dataout.UbuntuBootParamsPCRAlg != data.input.ubuntuBootParamsPCRAlg {
				t.Errorf("Unexpected ubuntu boot params PCR algorithm %v", dataout.UbuntuBootParamsPCRAlg)
			}
			if len(dataout.SecureBootORDigests) != len(data.input.secureBootPCRDigests) {
				t.Errorf("Unexpected number of secure boot OR digests")
			}
			if len(dataout.UbuntuBootParamsORDigests) != len(data.input.ubuntuBootParamsPCRDigests) {
				t.Errorf("Unexpected number of ubuntu boot params OR digests")
			}
			if dataout.PinIndexHandle != data.input.pinIndex.Handle() {
				t.Errorf("Unexpected PIN NV index handle")
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

			if !bytes.Equal(data.output, policy) {
				t.Errorf("Unexpected policy digest returned (got %x, expected %x)", policy, data.output)
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

	sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, defaultSessionHashAlgorithm, nil)
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
