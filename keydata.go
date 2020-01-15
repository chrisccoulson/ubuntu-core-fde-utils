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

	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"
)

const (
	currentVersion uint32 = 0
)

type auxData struct {
	PolicyData              *policyData
	PinIndexName            tpm2.Name
	PinIndexPolicyORDigests tpm2.DigestList
	PolicyRevokeIndexName   tpm2.Name
}

type keyData struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	KeyCreationData   *tpm2.CreationData
	KeyCreationTicket *tpm2.TkCreation
	AskForPinHint     bool
	AuxData           auxData
}

func (d *keyData) loadAndIntegrityCheck(buf io.Reader, tpm *tpm2.TPMContext, flushObjects bool) (
	tpm2.ResourceContext, error) {
	var version uint32
	if err := tpm2.UnmarshalFromReader(buf, &version); err != nil {
		return nil, fmt.Errorf("cannot unmarshal version number: %v", err)
	}

	if version != currentVersion {
		return nil, fmt.Errorf("unexpected version (%d)", version)
	}

	if err := tpm2.UnmarshalFromReader(buf, d); err != nil {
		return nil, fmt.Errorf("cannot unmarshal key data: %v", err)
	}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	flushOnExit := true

	// Load objects in to TPM
	keyContext, _, err := tpm.Load(srkContext, d.KeyPrivate, d.KeyPublic, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot load sealed key object in to TPM: %v", err)
	}
	defer func() {
		if !flushOnExit {
			return
		}
		tpm.FlushContext(keyContext)
	}()

	// The TPM performs integrity checking when loading objects to ensure that the public and private parts
	// are cryptographically bound. Perform some additional integrity checking here to ensure that the
	// various parts of keyData are cryptographically bound.

	// Verify that the creation data is cryptographically bound to the sealed key object
	h := sha256.New()
	if err := tpm2.MarshalToWriter(h, d.KeyCreationData); err != nil {
		return nil, fmt.Errorf("cannot hash creation data for sealed key object: %v", err)
	}

	_, _, err = tpm.CertifyCreation(nil, keyContext, nil, h.Sum(nil), nil, d.KeyCreationTicket, nil)
	if err != nil {
		switch e := err.(type) {
		case *tpm2.TPMParameterError:
			if e.Code() == tpm2.ErrorTicket {
				return nil, errors.New("integrity check of key data failed because the " +
					"creation data or creation ticket aren't cryptographically bound to the " +
					"sealed key object")
			}
		}
		return nil, fmt.Errorf("cannot perform integrity check as CertifyCreation failed: %v", err)
	}

	// The creation data in the keyData is cryptographically bound to the sealed key object (ie, it is the
	// one that the TPM returned when the sealed key object was created with the Create command. Now
	// verify that the digest of the auxiliary data matches that provided in the creation data.
	h = sha256.New()
	if err := tpm2.MarshalToWriter(h, d.AuxData); err != nil {
		return nil, fmt.Errorf("cannot hash auxiliary data: %v", err)
	}

	if !bytes.Equal(h.Sum(nil), d.KeyCreationData.OutsideInfo) {
		return nil, errors.New("integrity check of key data failed because the auxiliary data " +
			"is not cryptographically bound to the sealed key object")
	}

	// The auxiliary data is cryptographically bound to the sealed key object.

	// Now verify that the NV index used for the PIN is cryptographically bound to the sealed key object by
	// comparing its name with the name recorded in the auxiliary data.
	pinIndexContext, err := tpm.WrapHandle(d.AuxData.PolicyData.PinIndexHandle)
	if err != nil {
		switch e := err.(type) {
		case *tpm2.TPMHandleError:
			if e.Code() == tpm2.ErrorHandle {
				return nil,
					errors.New("integrity check of file failed because the NV index used " +
						"for the PIN has been deleted")
			}
		}
		return nil, fmt.Errorf("cannot obtain context for PIN NV index: %v", err)
	}

	if !bytes.Equal(d.AuxData.PinIndexName, pinIndexContext.Name()) {
		return nil, errors.New("integrity check of file failed because the NV index used for " +
			"the PIN is not cryptographically bound to the sealed key object")
	}

	// Now verify that the NV index used for policy revocation is cryptographucally bound to the sealed key
	// object by comparing its name with the name recorded in the auxiliary data.
	policyRevokeIndexContext, err := tpm.WrapHandle(d.AuxData.PolicyData.PolicyRevokeIndexHandle)
	if err != nil {
		switch e := err.(type) {
		case *tpm2.TPMHandleError:
			if e.Code() == tpm2.ErrorHandle {
				return nil,
					errors.New("integrity check of file failed because the NV index used " +
						"for authorization policy revocation has been deleted")
			}
		}
		return nil, fmt.Errorf("cannot obtain context for policy revocation NV index: %v", err)
	}

	if !bytes.Equal(d.AuxData.PolicyRevokeIndexName, policyRevokeIndexContext.Name()) {
		return nil, errors.New("integrity check of file failed because the NV index used for " +
			"authorization policy revocation is not cryptographically bound to the sealed key object")
	}

	// All good! All TPM objects pass the TPM's integrity checks, and external data is all cryptographically
	// bound too.

	if !flushObjects {
		flushOnExit = false
	}

	return keyContext, nil
}

func (d *keyData) writeToFile(dest string) error {
	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return err
	}
	defer f.Cancel()

	if err := tpm2.MarshalToWriter(f, currentVersion, d); err != nil {
		return fmt.Errorf("cannot marshal key data to temporary file: %v", err)
	}

	if err := f.Commit(); err != nil {
		return fmt.Errorf("cannot atomically replace file: %v", err)
	}

	return nil
}
