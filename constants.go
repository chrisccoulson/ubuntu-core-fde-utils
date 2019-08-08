package fdeutil

import (
	"github.com/chrisccoulson/go-tpm2"
)

const (
	srkHandle tpm2.Handle = 0x81000000

	pinSetHint uint8 = 1 << 0
)

var (
	paramEncryptAlg = tpm2.SymDef{
		Algorithm: tpm2.AlgorithmAES,
		KeyBits:   tpm2.SymKeyBitsU{Sym: 128},
		Mode:      tpm2.SymModeU{Sym: tpm2.AlgorithmCFB}}
)
