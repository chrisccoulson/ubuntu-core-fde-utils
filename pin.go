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
	"fmt"
	"os"

	"github.com/chrisccoulson/go-tpm2"
)

var (
	template = tpm2.Public{
		Type:    tpm2.AlgorithmKeyedHash,
		NameAlg: tpm2.AlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params: tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.AlgorithmNull}}}}
)

func createPINObject(tpm tpm2.TPMContext) (tpm2.Private, *tpm2.Public, error) {
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	sensitive := tpm2.SensitiveCreate{Data: []byte("PIN")}

	priv, pub, _, _, _, err := tpm.Create(srkContext, &sensitive, &template, nil, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create object: %v", err)
	}

	return priv, pub, nil
}

func ChangePIN(tpm tpm2.TPMContext, path string, oldAuth, newAuth string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open key data file: %v", err)
	}
	defer f.Close()

	var data keyData
	keyContext, pinContext, err := data.loadAndIntegrityCheck(f, tpm, false)
	if err != nil {
		return fmt.Errorf("cannot load DEK file: %v", err)
	}
	tpm.FlushContext(keyContext)
	defer tpm.FlushContext(pinContext)

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	sessionContext, err := tpm.StartAuthSession(srkContext, pinContext, tpm2.SessionTypeHMAC, &paramEncryptAlg,
		defaultHashAlgorithm, []byte(oldAuth))
	if err != nil {
		return fmt.Errorf("cannot start auth session: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	session := tpm2.Session{
		Context:   sessionContext,
		Attrs:     tpm2.AttrCommandEncrypt,
		AuthValue: []byte(oldAuth)}
	priv, err := tpm.ObjectChangeAuth(pinContext, srkContext, tpm2.Auth(newAuth), &session)
	if err != nil {
		return fmt.Errorf("cannot change PIN object authorization value: %v", err)
	}

	data.PinPrivate = priv
	if newAuth == "" {
		data.PinFlags = 0
	} else {
		data.PinFlags = pinSetHint
	}

	if err := data.writeToFile(path); err != nil {
		return fmt.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
