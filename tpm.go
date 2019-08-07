package fdeutil

import (
	"fmt"

	"github.com/chrisccoulson/go-tpm2"
)

const (
	tpmPath string = "/dev/tpm0"
)

func ConnectToDefaultTPM() (tpm2.TPMContext, error) {
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM device: %v", err)
	}

	tpm, _ := tpm2.NewTPMContext(tcti)
	return tpm, nil
}
