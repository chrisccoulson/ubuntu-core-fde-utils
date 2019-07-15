package fdeutil

import (
	"github.com/google/go-tpm/tpmutil"
)

const (
	srkHandle tpmutil.Handle = 0x81000000

	tpmPath string = "/dev/tpm0"
)
