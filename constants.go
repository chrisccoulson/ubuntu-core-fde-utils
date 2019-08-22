package fdeutil

import (
	"github.com/chrisccoulson/go-tpm2"
)

const (
	srkHandle tpm2.Handle = 0x81000000

	pinSetHint uint8 = 1 << 0

	// SHA-256 is mandatory to exist on every PC-Client TPM
	// FIXME: Dynamically select algorithms based on what's available on the device
	defaultHashAlgorithm tpm2.AlgorithmId = tpm2.AlgorithmSHA256
)

var (
	paramEncryptAlg = tpm2.SymDef{
		Algorithm: tpm2.AlgorithmAES,
		KeyBits:   tpm2.SymKeyBitsU{Sym: 128},
		Mode:      tpm2.SymModeU{Sym: tpm2.AlgorithmCFB}}
)
