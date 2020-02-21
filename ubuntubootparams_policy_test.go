package fdeutil

import (
	"bytes"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

func replayBootParamsToTPM(t *testing.T, tpm *TPMConnection, cmdline string) {
	cmdlineEvent := &tcglog.SystemdEFIStubEventData{Str: cmdline}
	var buf bytes.Buffer
	if err := cmdlineEvent.EncodeMeasuredBytes(&buf); err != nil {
		t.Fatalf("Cannot encode commandline: %v", err)
	}
	if _, err := tpm.PCREvent(tpm.PCRHandleContext(ubuntuBootParamsPCR), buf.Bytes(), nil); err != nil {
		t.Fatalf("PCREvent failed: %v", err)
	}
}

func TestComputeUbuntuBootParamsDigests(t *testing.T) {
	for _, data := range []struct{
		desc string
		alg tpm2.HashAlgorithmId
		commandlines []string
		digests tpm2.DigestList
	}{
		{
			desc: "SHA256",
			alg: tpm2.HashAlgorithmSHA256,
			commandlines: []string{
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
			},
			digests: tpm2.DigestList{
				tpm2.Digest{0xfc, 0x43, 0x3e, 0xaf, 0x03, 0x9c, 0x62, 0x61, 0xf4, 0x96, 0xa2, 0xa5, 0xbf, 0x2a, 0xdd, 0xfd, 0x8f, 0xf1, 0x10,
					0x4b, 0x0f, 0xc9, 0x8a, 0xf3, 0xfe, 0x95, 0x15, 0x17, 0xe3, 0xbd, 0xe8, 0x24},
				tpm2.Digest{0xb3, 0xa2, 0x90, 0x76, 0xee, 0xea, 0xe1, 0x97, 0xae, 0x72, 0x1c, 0x25, 0x4d, 0xa4, 0x04, 0x80, 0xb7, 0x66, 0x73,
					0x03, 0x80, 0x45, 0x30, 0x5c, 0xfa, 0x78, 0xec, 0x87, 0x42, 0x1c, 0x4e, 0xea}},
		},
		{
			desc: "SHA1",
			alg: tpm2.HashAlgorithmSHA1,
			commandlines: []string{
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
			},
			digests: tpm2.DigestList{
				tpm2.Digest{0xeb, 0x63, 0x12, 0xb7, 0xdb, 0x70, 0xfe, 0x16, 0x20, 0x6c, 0x16, 0x23, 0x26, 0xe3, 0x6b, 0x2f, 0xcd, 0xa7, 0x4b, 0x68},
				tpm2.Digest{0xbd, 0x61, 0x2b, 0xea, 0x9e, 0xfa, 0x58, 0x2f, 0xcb, 0xfa, 0xe9, 0x79, 0x73, 0xc8, 0x9b, 0x16, 0x37, 0x56, 0xfe, 0x0b}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			digests, err := computeUbuntuBootParamsDigests(data.alg, &PolicyParams{KernelCommandlines: data.commandlines})
			if err != nil {
				t.Fatalf("computeUbuntuBootParamsDigests failed: %v", err)
			}
			if len(digests) != len(data.digests) {
				t.Fatalf("Unexpected number of digests")
			}
			for i, d := range digests {
				if !bytes.Equal(d, data.digests[i]) {
					t.Errorf("Unexpected digest")
				}
			}
		})
	}
}
