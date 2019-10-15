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
	"github.com/chrisccoulson/go-tpm2"
)

const (
	srkHandle tpm2.Handle = 0x81000000

	pinSetHint uint8 = 1 << 0

	// SHA-256 is mandatory to exist on every PC-Client TPM
	// FIXME: Dynamically select algorithms based on what's available on the device
	defaultSessionHashAlgorithm tpm2.AlgorithmId = tpm2.AlgorithmSHA256
	sealedKeyNameAlgorithm      tpm2.AlgorithmId = tpm2.AlgorithmSHA256
)

var (
	paramEncryptAlg = tpm2.SymDef{
		Algorithm: tpm2.AlgorithmAES,
		KeyBits:   tpm2.SymKeyBitsU{Data: uint16(128)},
		Mode:      tpm2.SymModeU{Data: tpm2.AlgorithmCFB}}
)
