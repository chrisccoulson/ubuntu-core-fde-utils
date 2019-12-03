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
	"errors"
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"

	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"
)

const (
	currentVersion      uint32 = 0
	keyDataMagic        uint32 = 0x55534b24
	privateKeyDataMagic uint32 = 0x55534b50
)

type privateKeyData struct {
	AuthorizeKeyPrivate     []byte
	PolicyRevokeIndexHandle tpm2.Handle
	PolicyRevokeIndexName   tpm2.Name
}

type keyData struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AskForPinHint     bool
	StaticPolicyData  *staticPolicyData
	DynamicPolicyData *dynamicPolicyData
}

func readPrivateData(buf io.Reader) (*privateKeyData, error) {
	var magic uint32
	var version uint32
	if err := tpm2.UnmarshalFromReader(buf, &magic, &version); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal version number: %w", err)
	}

	if magic != privateKeyDataMagic {
		return nil, errors.New("unexpected file signature")
	}
	if version != currentVersion {
		return nil, fmt.Errorf("unexpected version number (%d)", version)
	}

	var d privateKeyData
	if err := tpm2.UnmarshalFromReader(buf, &d); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal key data: %w", err)
	}

	return &d, nil
}

func (d *privateKeyData) write(buf io.Writer) error {
	return tpm2.MarshalToWriter(buf, privateKeyDataMagic, currentVersion, d)
}

type keyFileError struct {
	err error
}

func (e keyFileError) Error() string {
	return e.err.Error()
}

func readKeyData(buf io.Reader) (*keyData, error) {
	var magic uint32
	var version uint32
	if err := tpm2.UnmarshalFromReader(buf, &magic, &version); err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot unmarshal version number: %w", err)}
	}

	if magic != keyDataMagic {
		return nil, keyFileError{errors.New("unexpected file signature")}
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

func loadKeyData(tpm *tpm2.TPMContext, buf io.Reader, session *tpm2.Session) (tpm2.ResourceContext, *keyData, error) {
	data, err := readKeyData(buf)
	if err != nil {
		return nil, nil, err
	}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	keyContext, _, err := tpm.Load(srkContext, data.KeyPrivate, data.KeyPublic, nil, session.AddAttrs(tpm2.AttrAudit))
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

func (d *keyData) write(buf io.Writer) error {
	return tpm2.MarshalToWriter(buf, keyDataMagic, currentVersion, d)
}

func (d *keyData) writeToFileAtomic(dest string) error {
	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	if err := tpm2.MarshalToWriter(f, keyDataMagic, currentVersion, d); err != nil {
		return xerrors.Errorf("cannot marshal key data to temporary file: %w", err)
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot atomically replace file: %w", err)
	}

	return nil
}
