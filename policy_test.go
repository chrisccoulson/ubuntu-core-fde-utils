package fdeutil

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
)

func computeSha256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func computeSha512(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

func TestComputePolicy(t *testing.T) {
	pinName, _ := tpm2.MarshalToBytes(tpm2.AlgorithmSHA256, tpm2.RawSlice(computeSha256([]byte("PIN"))))

	var sha256Digests tpm2.DigestList
	var sha512Digests tpm2.DigestList

	for _, data := range []string{"foo", "bar", "1234", "ABC"} {
		sha256Digests = append(sha256Digests, tpm2.Digest(computeSha256([]byte(data))))
		sha512Digests = append(sha512Digests, tpm2.Digest(computeSha512([]byte(data))))
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
						secureBootPCRAlg:     tpm2.AlgorithmSHA256,
						grubPCRAlg:           tpm2.AlgorithmSHA256,
						snapModelPCRAlg:      tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{sha256Digests[0]},
						grubPCRDigests:       tpm2.DigestList{sha256Digests[1]},
						snapModelPCRDigests:  tpm2.DigestList{sha256Digests[2]},
					},
				},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0x89, 0x01, 0x95, 0xd3, 0x1c, 0xf2, 0xfa, 0x32, 0x8c, 0x7d, 0xe2, 0xa4,
				0xcb, 0x32, 0xe6, 0xd3, 0x3e, 0x0a, 0x6a, 0x21, 0x07, 0x20, 0xfe, 0xf5, 0x8e, 0x43,
				0xd2, 0x07, 0x0f, 0x89, 0x2c, 0x8f},
		},
		{
			desc: "SingleSHA1",
			alg:  tpm2.AlgorithmSHA1,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg:     tpm2.AlgorithmSHA256,
						grubPCRAlg:           tpm2.AlgorithmSHA256,
						snapModelPCRAlg:      tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{sha256Digests[0]},
						grubPCRDigests:       tpm2.DigestList{sha256Digests[1]},
						snapModelPCRDigests:  tpm2.DigestList{sha256Digests[2]},
					},
				},
				pinObjectName: pinName,
			},
			output: tpm2.Digest{0x44, 0x63, 0x4f, 0xdf, 0xf1, 0x9b, 0xd1, 0xe6, 0x3c, 0x09, 0xd0, 0x8e,
				0x46, 0x7a, 0xec, 0xf7, 0x99, 0x17, 0x78, 0x08},
		},
		{
			desc: "SingleWithSHA512PCRs",
			alg:  tpm2.AlgorithmSHA256,
			input: policyComputeInput{
				subPolicies: []subPolicyComputeInput{
					{
						secureBootPCRAlg:     tpm2.AlgorithmSHA512,
						grubPCRAlg:           tpm2.AlgorithmSHA512,
						snapModelPCRAlg:      tpm2.AlgorithmSHA512,
						secureBootPCRDigests: tpm2.DigestList{sha512Digests[0]},
						grubPCRDigests:       tpm2.DigestList{sha512Digests[1]},
						snapModelPCRDigests:  tpm2.DigestList{sha512Digests[2]},
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
						secureBootPCRAlg:     tpm2.AlgorithmSHA256,
						grubPCRAlg:           tpm2.AlgorithmSHA256,
						snapModelPCRAlg:      tpm2.AlgorithmSHA512,
						secureBootPCRDigests: tpm2.DigestList{sha256Digests[0], sha256Digests[1]},
						grubPCRDigests:       tpm2.DigestList{sha256Digests[3], sha256Digests[2]},
						snapModelPCRDigests:  tpm2.DigestList{sha512Digests[2]},
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
						secureBootPCRAlg:     tpm2.AlgorithmSHA256,
						grubPCRAlg:           tpm2.AlgorithmSHA256,
						snapModelPCRAlg:      tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{sha256Digests[0]},
						grubPCRDigests:       tpm2.DigestList{sha256Digests[1], sha256Digests[2]},
						snapModelPCRDigests:  tpm2.DigestList{sha256Digests[2]},
					},
					{
						secureBootPCRAlg:     tpm2.AlgorithmSHA256,
						grubPCRAlg:           tpm2.AlgorithmSHA256,
						snapModelPCRAlg:      tpm2.AlgorithmSHA256,
						secureBootPCRDigests: tpm2.DigestList{sha256Digests[1]},
						grubPCRDigests:       tpm2.DigestList{sha256Digests[2], sha256Digests[3]},
						snapModelPCRDigests:  tpm2.DigestList{sha256Digests[2]},
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
