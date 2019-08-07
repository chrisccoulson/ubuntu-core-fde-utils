package fdeutil

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealAndUnseal(t *testing.T) {
	tpm := openTPMForTesting(t)
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

	key := make([]byte, 64)
	rand.Read(key)

	buf := new(bytes.Buffer)
	if err := SealKeyToTPM(tpm, buf, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, buf)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}
