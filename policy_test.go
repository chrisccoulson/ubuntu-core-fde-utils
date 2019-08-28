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
			desc: "SingleCompoundSecureBootPolicy",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinObjectName:       pinName,
			},
			output: tpm2.Digest{0xd1, 0xaa, 0x73, 0x0a, 0xbb, 0xe7, 0x8a, 0xef, 0x69, 0x84, 0x2e, 0x74,
				0x3b, 0xe8, 0x01, 0x12, 0x5a, 0xdd, 0xb0, 0xb5, 0x77, 0x8d, 0x87, 0x63, 0x1e, 0x7f,
				0x23, 0xfc, 0x78, 0x11, 0x57, 0xff},
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinObjectName:       pinName,
			},
			output: tpm2.Digest{0x91, 0x0a, 0x90, 0x04, 0xc5, 0x18, 0xf5, 0xd7, 0xe6, 0xf1, 0x1a, 0x9b,
				0x29, 0xc4, 0x65, 0xf4, 0xf3, 0xfd, 0x1b, 0x36},
		},
		{
			desc: "SHA256SessionWithSHA512PCRs",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA512,
						grubPCRAlg:       tpm2.AlgorithmSHA512,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA512][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA512][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA512,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA512][2]},
				pinObjectName:       pinName,
			},
			output: tpm2.Digest{0xdc, 0x50, 0xbc, 0x6c, 0x83, 0x52, 0x86, 0x7f, 0x43, 0x6d, 0x46, 0xab,
				0xb5, 0x76, 0x86, 0xa6, 0x44, 0xf9, 0xfb, 0xc2, 0xdf, 0x92, 0xff, 0x80, 0x05, 0xc7,
				0xe0, 0x17, 0x2d, 0xbc, 0x39, 0x38},
		},
		{
			desc: "SingleCompoundSecureBootPolicyWithMultiplePCRValues",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0],
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3],
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA512,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA512][2]},
				pinObjectName:       pinName,
			},
			output: tpm2.Digest{0xb5, 0x39, 0x06, 0xc9, 0x79, 0x71, 0x74, 0xf2, 0x4e, 0x82, 0x4e, 0xbe,
				0xe9, 0x15, 0x8e, 0xfa, 0x5c, 0x8b, 0x2c, 0xd5, 0x52, 0x6d, 0xd1, 0x3b, 0x56, 0xf1,
				0x25, 0x21, 0x15, 0x72, 0xc0, 0x78},
		},
		{
			desc: "MultipleCompoundSecureBootPolicies",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1],
							digestMatrix[tpm2.AlgorithmSHA256][2]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][2],
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][2]},
				pinObjectName:       pinName,
			},
			output: tpm2.Digest{0x0f, 0x22, 0x4b, 0xe9, 0x22, 0xb8, 0xc1, 0xa6, 0x54, 0x2d, 0x4b, 0xed,
				0x17, 0x6c, 0xff, 0x84, 0x25, 0xc1, 0x96, 0x27, 0x99, 0xf4, 0xfe, 0x78, 0x20, 0x1d,
				0x70, 0x08, 0x05, 0x8a, 0xdd, 0x8c},
		},
		{
			desc: "MultipleSnapModels",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg: tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][2],
					digestMatrix[tpm2.AlgorithmSHA256][3]},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0x25, 0xc6, 0xaa, 0x3f, 0x05, 0xdd, 0xc0, 0x52, 0x60, 0x2d, 0x1f, 0x97,
				0xf5, 0x80, 0x5e, 0xf9, 0x04, 0xfd, 0x13, 0x32, 0xe2, 0x34, 0x96, 0x06, 0xb4, 0x4c,
				0x93, 0xd8, 0x98, 0xd6, 0x9c, 0xd8},
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
			if len(dataout.SbPolicyORDigests) != len(data.input.compoundSbPolicies) {
				t.Errorf("Unexpected number of compound secure-boot policy OR digests")
			}
			if len(dataout.SbPolicyData) != len(data.input.compoundSbPolicies) {
				t.Fatalf("Unexpected number of compound secure-boot policy data structures")
			}
			digestSize := getDigestSize(data.alg)
			for i := 0; i < len(data.input.compoundSbPolicies); i++ {
				if dataout.SbPolicyData[i].SecureBootPCRAlg !=
					data.input.compoundSbPolicies[i].secureBootPCRAlg {
					t.Errorf("Unexpected secure boot PCR algorithm %v for index %d",
						dataout.SbPolicyData[i].SecureBootPCRAlg, i)
				}
				if dataout.SbPolicyData[i].GrubPCRAlg !=
					data.input.compoundSbPolicies[i].grubPCRAlg {
					t.Errorf("Unexpected grub PCR algorithm %v for index %d",
						dataout.SbPolicyData[i].GrubPCRAlg, i)
				}
				for _, l := range []tpm2.DigestList{dataout.SbPolicyData[i].SecureBootORDigests,
					dataout.SbPolicyData[i].GrubORDigests} {
					for _, digest := range l {
						if len(digest) != int(digestSize) {
							t.Errorf("Unexpected digest size")
						}
					}
				}
				for _, digest := range dataout.SbPolicyORDigests {
					if len(digest) != int(digestSize) {
						t.Errorf("Unexpected digest size")
					}
				}
			}
			if dataout.SnapModelPCRAlg != data.input.snapModelPCRAlg {
				t.Errorf("Unexpected snap model PCR algorithm %v", dataout.SnapModelPCRAlg)
			}
			if len(dataout.SnapModelORDigests) != len(data.input.snapModelPCRDigests) {
				t.Errorf("Unexpected number of snap model policy OR digests")
			}
			for _, digest := range dataout.SnapModelORDigests {
				if len(digest) != int(digestSize) {
					t.Errorf("Unexpected digest size")
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
			desc: "SingleCompoundSecureBootPolicy",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
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
			match: true,
		},
		{
			desc: "SHA1SessionWithSHA256PCRs",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
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
			match: true,
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA1,
						grubPCRAlg:       tpm2.AlgorithmSHA1,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA1][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA1][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA1,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA1][2]},
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
			match: true,
		},
		{
			desc: "WithPIN",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
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
			pinDefine: "1234",
			pinInput:  "1234",
			match:     true,
		},
		{
			desc: "WithIncorrectPIN",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
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
			pinDefine: "1234",
			pinInput:  "12345",
			errMsg: "cannot execute PolicySecret command: TPM returned an error for session 1 " +
				"whilst executing command TPM_CC_PolicySecret: TPM_RC_AUTH_FAIL (the " +
				"authorization HMAC check failed and DA counter incremented)",
			match: false,
		},
		{
			desc: "SingleCompoundSecureBootPolicyNoMatch",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
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
			match: false,
		},
		{
			desc: "SingleCompoundSecureBootPolicyWithMultiplePCRValues1",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1],
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
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
			match: true,
		},
		{
			desc: "SingleCompoundSecureBootPolicyWithMultiplePCRValues2",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1],
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
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
			match: true,
		},
		{
			desc: "MultipleCompoundSecureBootPolicies1",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][4]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][4]},
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
					data:  "5678",
				},
			},
			match: true,
		},
		{
			desc: "MultipleCompoundSecureBootPolicies2",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][4]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][4]},
				pinObjectName:       pinName,
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
					data:  "5678",
				},
			},
			match: true,
		},
		{
			desc: "MultipleCompoundSecureBootPoliciesNoMatch",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][3]},
					},
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][4]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg:     tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{digestMatrix[tpm2.AlgorithmSHA256][4]},
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
					data:  "5678",
				},
			},
			match: false,
		},
		{
			desc: "MultipleSnapModels",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				compoundSbPolicies: []compoundSbPolicyComputeInput{
					{
						secureBootPCRAlg: tpm2.AlgorithmSHA256,
						grubPCRAlg:       tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][0]},
						grubPCRDigests: tpm2.DigestList{
							digestMatrix[tpm2.AlgorithmSHA256][1]},
					},
				},
				snapModelPCRAlg: tpm2.AlgorithmSHA256,
				snapModelPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.AlgorithmSHA256][2],
					digestMatrix[tpm2.AlgorithmSHA256][4]},
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
					data:  "5678",
				},
			},
			match: true,
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
