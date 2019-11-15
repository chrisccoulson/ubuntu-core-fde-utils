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

	"golang.org/x/xerrors"
)

const (
	currentVersion uint32 = 0
)

type boundKeyData struct {
	PinIndexName          tpm2.Name
	PolicyRevokeIndexName tpm2.Name
}

type keyData struct {
	KeyPrivate              tpm2.Private
	KeyPublic               *tpm2.Public
	KeyCreationData         *tpm2.CreationData
	KeyCreationTicket       *tpm2.TkCreation
	AskForPinHint           bool
	PolicyData              *policyData
	PinIndexPolicyORDigests tpm2.DigestList
	BoundData               *boundKeyData
}

type keyFileError struct {
	err error
}

func (e keyFileError) Error() string {
	return e.err.Error()
}

func readKeyData(buf io.Reader) (*keyData, error) {
	var version uint32
	if err := tpm2.UnmarshalFromReader(buf, &version); err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot unmarshal version number: %w", err)}
	}

	if version != currentVersion {
		return nil, keyFileError{fmt.Errorf("unexpected version number (%d)", version)}
	}

	var d keyData
	if err := tpm2.UnmarshalFromReader(buf, &d); err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot unmarshal key data: %w", err)}
	}

	return &d, nil
}

func loadKeyData(tpm *tpm2.TPMContext, buf io.Reader) (tpm2.ResourceContext, *keyData, error) {
	data, err := readKeyData(buf)
	if err != nil {
		return nil, nil, err
	}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	keyContext, _, err := tpm.Load(srkContext, data.KeyPrivate, data.KeyPublic, nil)
	if err != nil {
		invalidObject := false
		switch e := err.(type) {
		case *tpm2.TPMParameterError:
			_ = e
			invalidObject = true
		case *tpm2.TPMError:
			if e.Code == tpm2.ErrorSensitive {
				invalidObject = true
			}
		}
		if invalidObject {
			return nil, nil, keyFileError{errors.New("bad sealed key object or TPM owner changed")}
		}
		return nil, nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}

	return keyContext, data, nil
}

func readAndIntegrityCheckKeyData(tpm *tpm2.TPMContext, buf io.Reader, session *tpm2.Session) (*keyData, error) {
	context, data, err := loadKeyData(tpm, buf)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(context)

	// The TPM performs integrity checking when loading objects to ensure that the public and private parts are cryptographically
	// bound. Perform some additional integrity checking here to ensure that parts of keyData that are used to compute
	// authorization policies are cryptographically bound to the sealed key object and haven't been modified offline.

	// Verify that the creation data is cryptographically bound to the sealed key object
	h := tpm2.HashAlgorithmSHA256.NewHash()
	if err := tpm2.MarshalToWriter(h, data.KeyCreationData); err != nil {
		// We've just unmarshalled this - it shouldn't fail
		panic(fmt.Sprintf("cannot hash creation data for sealed key object: %v", err))
	}

	_, _, err = tpm.CertifyCreation(nil, context, nil, h.Sum(nil), nil, data.KeyCreationTicket, nil, session.AddAttrs(tpm2.AttrAudit))
	if err != nil {
		var e *tpm2.TPMError
		if xerrors.As(err, &e) && e.Code == tpm2.ErrorTicket {
			return nil, keyFileError{errors.New("integrity check of key data failed because the creation data or creation ticket aren't " +
				"cryptographically bound to the sealed key object")}
		}
		return nil, xerrors.Errorf("cannot complete integrity checks as CertifyCreation failed: %w", err)
	}

	// The creation data is cryptographically bound to the sealed key object (ie, it is the one that the TPM returned when the
	// sealed key object was created with the TPM2_Create command. Now verify that the digest of the bound auxiliary data matches
	// that contained in the verified creation data.
	h = sha256.New()
	if err := tpm2.MarshalToWriter(h, data.BoundData); err != nil {
		// We've just unmarshalled this - it shouldn't fail
		panic(fmt.Sprintf("cannot hash auxiliary data for sealed key object: %v", err))
	}

	if !bytes.Equal(h.Sum(nil), data.KeyCreationData.OutsideInfo) {
		return nil, keyFileError{errors.New("integrity check of key data failed because the auxiliary data is not cryptographically " +
			"bound to the sealed key object")}
	}

	// At this point, the bound auxiliary data is cryptographically bound to the sealed key object. The names of the NV indices
	// contained within it are the ones used to create the initial authorization policy for the sealed key object.

	return data, nil
}

func (d *keyData) writeToFile(dest string) error {
	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	if err := tpm2.MarshalToWriter(f, currentVersion, d); err != nil {
		return xerrors.Errorf("cannot marshal key data to temporary file: %w", err)
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot atomically replace file: %w", err)
	}

	return nil
}
