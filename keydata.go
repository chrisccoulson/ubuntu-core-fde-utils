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
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

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
	Data struct {
		AuthorizeKeyPrivate     []byte
		PolicyRevokeIndexHandle tpm2.Handle
		PolicyRevokeIndexName   tpm2.Name
	}
	CreationData   *tpm2.CreationData
	CreationTicket *tpm2.TkCreation
}

type keyData struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AskForPinHint     bool
	PinIndexKeyName   tpm2.Name
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

func (d *keyData) validate(tpm *tpm2.TPMContext, privateData *privateKeyData, session *tpm2.Session) error {
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	// Load the sealed data object in to the TPM for integrity checking
	keyContext, _, err := tpm.Load(srkContext, d.KeyPrivate, d.KeyPublic, nil, session.AddAttrs(tpm2.AttrAudit))
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
			return keyFileError{errors.New("bad sealed key object or TPM owner changed")}
		}
		return xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}
	// It's loaded ok, so we know that the private and public parts are consistent.
	defer tpm.FlushContext(keyContext)

	// Obtain a ResourceContext for the PIN NV index. Go-tpm2 uses TPM2_NV_ReadPublic without any integrity protection here to
	// initialize the ResourceContext.
	if d.StaticPolicyData.PinIndexHandle.Type() != tpm2.HandleTypeNVIndex {
		return keyFileError{errors.New("PIN NV index handle is invalid")}
	}
	pinIndex, err := tpm.WrapHandle(d.StaticPolicyData.PinIndexHandle)
	if err != nil {
		if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
			return keyFileError{errors.New("PIN NV index is unavailable")}
		}
		return xerrors.Errorf("cannot create context for PIN NV index: %w", err)
	}
	// Call TPM2_NV_ReadPublic with an audit session for integrity protection purposes and make sure that the returned name matches
	// the name read back when initializing the ResourceContext.
	pinIndexPublic, pinIndexName, err := tpm.NVReadPublic(pinIndex, session.AddAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area for PIN NV index: %w", err)
	}
	if !bytes.Equal(pinIndexName, pinIndex.Name()) {
		return errors.New("invalid context for PIN NV index")
	}

	authKeyName, err := d.StaticPolicyData.AuthorizeKeyPublic.Name()
	if err != nil {
		return keyFileError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
	}
	if d.StaticPolicyData.AuthorizeKeyPublic.Type != tpm2.ObjectTypeRSA {
		return keyFileError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	trial, _ := tpm2.ComputeAuthPolicy(sealedKeyNameAlgorithm)
	trial.PolicyAuthorize(nil, authKeyName)
	trial.PolicySecret(pinIndex.Name(), nil)

	if !bytes.Equal(trial.GetDigest(), d.KeyPublic.AuthPolicy) {
		return keyFileError{errors.New("static authorization policy data doesn't match sealed key object")}
	}

	// Make sure that the name of the key used to initialize the PIN NV index is consistent with the public area of the index.
	// We've already verified that the NV index is correct in the previous step.
	policies := pinNvIndexAuthPolicies(d.PinIndexKeyName)
	trial, _ = tpm2.ComputeAuthPolicy(pinNvIndexNameAlgorithm)
	trial.PolicyOR(policies)
	if !bytes.Equal(trial.GetDigest(), pinIndexPublic.AuthPolicy) {
		return keyFileError{errors.New("PIN NV index key name is inconsistent with public area")}
	}

	// At this point, we know that the public area of the dynamic authorization policy signing key and the PIN NV index are consistent
	// with the sealed data object.

	if privateData == nil {
		// If we weren't passed a private data structure, we're done.
		return nil
	}

	// Verify that the private data structure is bound to the key data structure.
	h := d.KeyPublic.NameAlg.NewHash()
	if err := tpm2.MarshalToWriter(h, privateData.CreationData); err != nil {
		panic(fmt.Sprintf("cannot marshal creation data: %v", err))
	}

	if _, _, err := tpm.CertifyCreation(nil, keyContext, nil, h.Sum(nil), nil, privateData.CreationTicket, nil,
		session.AddAttrs(tpm2.AttrAudit)); err != nil {
		switch e := err.(type) {
		case *tpm2.TPMParameterError:
			if e.Index == 4 {
				return keyFileError{errors.New("key data file and private data file mismatch: invalid creation ticket")}
			}
		}
		return xerrors.Errorf("cannot validate creation data for sealed data object: %w", err)
	}

	h = crypto.SHA256.New()
	if err := tpm2.MarshalToWriter(h, &privateData.Data); err != nil {
		panic(fmt.Sprintf("cannot marshal private data: %v", err))
	}

	if !bytes.Equal(h.Sum(nil), privateData.CreationData.OutsideInfo) {
		return keyFileError{errors.New("key data file and private data file mismatch: digest doesn't match creation data")}
	}

	authKeyPrivate, err := x509.ParsePKCS1PrivateKey(privateData.Data.AuthorizeKeyPrivate)
	if err != nil {
		return keyFileError{xerrors.Errorf("cannot parse dynamic policy authorization key: %w", err)}
	}

	if privateData.Data.PolicyRevokeIndexHandle.Type() != tpm2.HandleTypeNVIndex {
		return keyFileError{errors.New("dynamic authorization policy revocation NV index handle is invalid")}
	}
	// Obtain a ResourceContext for the policy revocation NV index. Go-tpm2 uses TPM2_NV_ReadPublic without any integrity protection
	// here to initialize the ResourceContext.
	policyRevokeIndex, err := tpm.WrapHandle(privateData.Data.PolicyRevokeIndexHandle)
	if err != nil {
		if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
			return keyFileError{errors.New("dynamic authorization policy revocation NV index is unavailable")}
		}
		return xerrors.Errorf("cannot create context for dynamic authorization policy revocation NV index: %w", err)
	}
	// Call TPM2_NV_ReadPublic with an audit session for integrity protection purposes and make sure that the returned name matches
	// the name read back when initializing the ResourceContext.
	_, policyRevokeIndexName, err := tpm.NVReadPublic(policyRevokeIndex, session.AddAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area for dynamic authorization policy revocation NV index: %w", err)
	}
	if !bytes.Equal(policyRevokeIndexName, policyRevokeIndex.Name()) {
		return errors.New("invalid context for dynamic authorization policy revocation NV index")
	}
	if !bytes.Equal(privateData.Data.PolicyRevokeIndexName, policyRevokeIndex.Name()) {
		return keyFileError{errors.New("dynamic authorization policy revocation NV index has the wrong name")}
	}

	authKey := rsa.PublicKey{
		N: new(big.Int).SetBytes(d.StaticPolicyData.AuthorizeKeyPublic.Unique.RSA()),
		E: int(d.StaticPolicyData.AuthorizeKeyPublic.Params.RSADetail().Exponent)}
	if authKeyPrivate.PublicKey.E != authKey.E || authKeyPrivate.PublicKey.N.Cmp(authKey.N) != 0 {
		return keyFileError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return nil
}
