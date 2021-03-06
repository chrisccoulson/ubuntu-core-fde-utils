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
	"crypto/rsa"
	"fmt"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func isAuthFailError(err error) bool {
	var sessionErr *tpm2.TPMSessionError
	if !xerrors.As(err, &sessionErr) {
		return false
	}
	switch sessionErr.Code() {
	case tpm2.ErrorAuthFail: // With DA implications
		return true
	case tpm2.ErrorBadAuth: // Without DA implications
		return true
	}
	return false
}

func isLockoutError(err error) bool {
	var warning *tpm2.TPMWarning
	return xerrors.As(err, &warning) && warning.Code == tpm2.WarningLockout
}

type nvIndexDefinedError struct {
	handle tpm2.Handle
}

func (e *nvIndexDefinedError) Error() string {
	return fmt.Sprintf("NV index defined at 0x%08x", e.handle)
}

func isNVIndexDefinedWithHandleError(err error) bool {
	var e *nvIndexDefinedError
	return xerrors.As(err, &e)
}

func isNVIndexDefinedError(err error) bool {
	var tpmErr *tpm2.TPMError
	return xerrors.As(err, &tpmErr) && tpmErr.Code == tpm2.ErrorNVDefined
}

func createPublicAreaForRSASigningKey(key *rsa.PublicKey) *tpm2.Public {
	return &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   uint16(key.N.BitLen()),
				Exponent:  uint32(key.E)}},
		Unique: tpm2.PublicIDU{Data: tpm2.PublicKeyRSA(key.N.Bytes())}}
}

type pcr struct {
	alg   tpm2.HashAlgorithmId
	value tpm2.Digest
}

func (p *pcr) extend(d tpm2.Digest) {
	if len(p.value) != len(d) {
		panic("invalid digest length")
	}

	h := p.alg.NewHash()
	h.Write(p.value)
	h.Write(d)

	copy(p.value, h.Sum(nil))
}

func newSimulatedPCR(alg tpm2.HashAlgorithmId) *pcr {
	return &pcr{alg: alg, value: make(tpm2.Digest, alg.Size())}
}
