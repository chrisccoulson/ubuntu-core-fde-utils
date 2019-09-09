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
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/google/renameio"
)

const (
	currentVersion uint32 = 0
)

type auxData struct {
	PolicyData    *policyData
	PinObjectName tpm2.Name
}

type keyData struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	KeyCreationData   *tpm2.CreationData
	KeyCreationTicket *tpm2.TkCreation
	PinPrivate        tpm2.Private
	PinPublic         *tpm2.Public
	PinFlags          uint8
	AuxData           auxData
}

func (d *keyData) loadAndIntegrityCheck(buf io.Reader, tpm tpm2.TPMContext,
	flushObjects bool) (tpm2.ResourceContext, tpm2.ResourceContext, error) {
	var version uint32
	if err := tpm2.UnmarshalFromReader(buf, &version); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal version number: %v", err)
	}

	if version != currentVersion {
		return nil, nil, fmt.Errorf("unexpected version (%d)", version)
	}

	if err := tpm2.UnmarshalFromReader(buf, d); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal key data: %v", err)
	}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	flushOnExit := true

	// Load objects in to TPM
	keyContext, _, err := tpm.Load(srkContext, d.KeyPrivate, d.KeyPublic, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load sealed key object in to TPM: %v", err)
	}
	defer func() {
		if !flushOnExit {
			return
		}
		tpm.FlushContext(keyContext)
	}()

	pinContext, _, err := tpm.Load(srkContext, d.PinPrivate, d.PinPublic, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load PIN object in to TPM: %v", err)
	}
	defer func() {
		if !flushOnExit {
			return
		}
		tpm.FlushContext(pinContext)
	}()

	// The TPM performs integrity checking when loading objects to ensure that the public and private parts
	// are cryptographically bound. Perform some additional integrity checking here to ensure that the
	// various parts of keyData are cryptographically bound.

	// Verify that the creation data is cryptographically bound to the sealed key object
	h := sha256.New()
	if err := tpm2.MarshalToWriter(h, d.KeyCreationData); err != nil {
		return nil, nil, fmt.Errorf("cannot hash creation data for sealed key object: %v", err)
	}

	_, _, err = tpm.CertifyCreation(nil, keyContext, nil, h.Sum(nil), nil, d.KeyCreationTicket, nil)
	if err != nil {
		switch e := err.(type) {
		case tpm2.TPMParameterError:
			if e.Code == tpm2.ErrorTicket {
				return nil, nil, errors.New("integrity check of key data failed because the " +
					"creation data or creation ticket aren't cryptographically bound to the " +
					"sealed key object")
			}
		}
		return nil, nil, fmt.Errorf("cannot perform integrity check as CertifyCreation failed: %v", err)
	}

	// The creation data in the keyData is cryptographically bound to the sealed key object (ie, it is the
	// one that the TPM returned when the sealed key object was created with the Create command. Now
	// verify that the digest of the auxiliary data matches that provided in the creation data.
	h = sha256.New()
	if err := tpm2.MarshalToWriter(h, d.AuxData); err != nil {
		return nil, nil, fmt.Errorf("cannot hash auxiliary data: %v", err)
	}

	if !bytes.Equal(h.Sum(nil), d.KeyCreationData.OutsideInfo) {
		return nil, nil, errors.New("integrity check of key data failed because the auxiliary data " +
			"is not cryptographically bound to the sealed key object")
	}

	// The auxiliary data is cryptographically bound to the sealed key object. Now verify that the PIN object
	// and sealed key object are cryptographically bound by comparing the name of the PIN object with the
	// name in the auxiliary data.
	if !bytes.Equal(d.AuxData.PinObjectName, pinContext.Name()) {
		return nil, nil, errors.New("integrity check of file failed because the PIN object doesn't " +
			"belong to the sealed key object")
	}

	// All good! All TPM objects pass the TPM's integrity checks, and external data is all cryptographically
	// bound too.

	if !flushObjects {
		flushOnExit = false
	}

	return keyContext, pinContext, nil
}

func (d *keyData) writeToFile(dest string) error {
	f, err := renameio.TempFile("", dest)
	if err != nil {
		return fmt.Errorf("cannot open temporary file: %v", err)
	}
	defer f.Cleanup()

	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("cannot set permissions on temporary file: %v", err)
	}

	if err := tpm2.MarshalToWriter(f, currentVersion, d); err != nil {
		return fmt.Errorf("cannot marshal key data to temporary file: %v", err)
	}

	if err := f.CloseAtomicallyReplace(); err != nil {
		return fmt.Errorf("cannot atomically replace file: %v", err)
	}

	return nil
}
