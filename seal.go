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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/snapcore/snapd/snap"

	"golang.org/x/xerrors"
)

type OSComponentImage interface {
	ReadAll() ([]byte, error)
}

type SnapFileOSComponent struct {
	Container snap.Container
	FileName  string
}

func (f SnapFileOSComponent) ReadAll() ([]byte, error) {
	return f.Container.ReadFile(f.FileName)
}

type FileOSComponent string

func (p FileOSComponent) ReadAll() ([]byte, error) {
	f, err := os.Open(string(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

// OSComponentLoadType describes how an OS component in a boot sequence that should be permitted to unseal the disk
// encryption key is loaded by the previous component.
type OSComponentLoadType int

const (
	// FirmwareLoad corresponds to a component that is loaded via EFI_BOOT_SERVICES.LoadImage() and
	// EFI_BOOT_SERVICES.StartImage(), being verified by UEFI firmware using a signature from the UEFI
	// signature database.
	FirmwareLoad OSComponentLoadType = iota

	// DirectLoadWithShimVerify corresponds to a component that is loaded directly without the assistance of
	// UEFI boot services APIs, being verified using Shim's UEFI protocol using a signature from the UEFI
	// signature database, a machine-owner key, or Shim's vendor certificate.
	DirectLoadWithShimVerify
)

// OSComponent corresponds to a single OS component in a boot sequence that should be permitted to unseal the disk
// encryption key. These form a tree representing alternate sequences.
type OSComponent struct {
	LoadType OSComponentLoadType // How the component is loaded and verified by the previous component
	Image    OSComponentImage    // The raw image of this component
	Next     []*OSComponent      // The next components for each permitted boot path
}

// SealParams contains parameters used for computation of the authorization policy for the sealed key object.
type SealParams struct {
	// LoadPaths corresponds to alternate trees of OSComponent structures corresponding to the boot sequences
	// that should be permitted to unseal the disk encryption key. The root of each tree must have LoadType
	// set to FirmwareLoad.
	// To support atomic updates of a component (eg, a kernel), SealKeyToTPM should be called before an
	// update is committed with boot sequences containing both the old and new components. If the old and
	// new components are signed with different keys, then this will automatically be reflected in the
	// generated authorization policy. Alternate boot sequences resulting in the same authorization policy
	// are automatically de-duplicated.
	LoadPaths []*OSComponent
}

type CreationParams struct {
	PolicyRevocationHandle tpm2.Handle
	PinHandle              tpm2.Handle
	OwnerAuth              []byte
}

func isNVIndexDefinedError(err error) bool {
	var tpmError *tpm2.TPMError
	if !xerrors.As(err, &tpmError) {
		return false
	}
	if tpmError.Code != tpm2.ErrorNVDefined {
		return false
	}
	if tpmError.Command != tpm2.CommandNVDefineSpace {
		return false
	}
	return true
}

// SealKeyToTPM seals the provided disk encryption key to the storage hierarchy of a TPM. The caller is required to provide a
// connection to the TPM. The sealed key object and associated metadata (creation data and ticket for sealed key object, PIN data
// and auxiliary policy data) are all written to the file specified by dest.
//
// If the TPM is not correctly provisioned with a persistent storage root key at the expected location, it will return a
// ErrProvisioning error. In this case, ProvisionTPM must be called before proceeding.
//
// The authorization policy for sealed key object will be computed based on params.
//
// If called with a non-nil create parameter, a new file will be created and this function will return a ErrKeyFileExists error if
// there is already a file with the same name. In this mode, the caller is expected to provide handles at which NV indices should be
// created for policy revocation and PIN support via the PolicyRevocationHandle and PinHandle fields of the CreationParams struct.
// If either handle is already in use, a TPMResourceExistsError error will be returned. The handles must be valid NV index handles
// (MSO == 0x01), and the choice of handle should take in to consideration the reserved indices from the "Registry of reserved TPM 2.0
// handles and localities" specification. It is recommended that the handles are in the block reserved for owner objects (0x01800000 -
// 0x01bfffff). When called in this mode, the owner authorization is also required, provided via the OwnerAuth of the CreationParams
// struct. If the provided owner authorization is incorrect, a AuthFailError error will be returned. On a TPM that has been newly
// provisioned with ProvisionTPM, the owner authorization is empty and the nil value can be passed here.
//
// If called with a nil create parameter, this function operates in "reseal" mode where the provided key is sealed in the same way as
// the create mode, including with an updated authorization policy. However, in this mode, other resources (eg, NV indices) associated
// with the key are preserved. In this mode, a valid key data file is expected to be at the location specified by dest, and NV indices
// associated with the key data file are expected to be present on the TPM. If the key data file cannot be opened, a wrapped
// *os.PathError error will be returned. If the file contains invalid components, fails any integrity checks, or any associated TPM
// resources are invalid, a InvalidKeyFileError will be returned.
func SealKeyToTPM(tpm *TPMConnection, dest string, create *CreationParams, params *SealParams, key []byte) error {
	// Check that the key is the correct length
	if len(key) != 64 {
		return fmt.Errorf("expected a key length of 512 bits (got %d)", len(key)*8)
	}

	// Use the HMAC session created when the connection was opened rather than creating a new one.
	session := tpm.HmacSession()

	// Bail out now if the object at the SRK index obviously isn't a valid primary key with the expected properties, as we know
	// that a future call to ProvisionTPM will create a different key that makes the sealed key object non-recoverable. If this
	// succeeds, it doesn't necessarily mean that the object was created with the same template that ProvisionTPM uses, and isn't
	// a guarantee that a future call to ProvisionTPM would't produce a different key.
	//
	// Ideally, initial creation would be performed immediately after ProvisionTPM without closing the TPMConnection, as ProvisionTPM
	// will cache a ResourceContext for the SRK it creates and if the object is switched out on the TPM for a different one in the
	// meantime, TPM2_Create will fail later on.
	if ok, err := hasValidSRK(tpm.TPMContext, session); err != nil {
		return err
	} else if !ok {
		return ErrProvisioning
	}
	// This can't fail now
	srkContext, _ := tpm.WrapHandle(srkHandle)

	// At this point, we know that the name and public area associated with srkContext correspond to an object on the TPM.

	var err error

	var pinIndex tpm2.ResourceContext
	var askForPinHint bool

	var policyRevokeIndex tpm2.ResourceContext

	// If we are creating a new sealed key object, create the associated NV indices
	if create != nil {
		if _, err := os.Stat(dest); err == nil || !os.IsNotExist(err) {
			return ErrKeyFileExists
		}

		pinIndex, err = createPinNvIndex(tpm.TPMContext, create.PinHandle, create.OwnerAuth, session)
		if err != nil {
			switch {
			case isNVIndexDefinedError(err):
				return TPMResourceExistsError{create.PinHandle}
			case isAuthFailError(err):
				return AuthFailError{tpm2.HandleOwner}
			}
			return xerrors.Errorf("cannot create new pin NV index: %w", err)
		}

		policyRevokeIndex, err = createPolicyRevocationNvIndex(tpm.TPMContext, create.PolicyRevocationHandle, create.OwnerAuth, session)
		if err != nil {
			switch {
			case isNVIndexDefinedError(err):
				return TPMResourceExistsError{create.PolicyRevocationHandle}
			case isAuthFailError(err):
				return AuthFailError{tpm2.HandleOwner}
			}
			return xerrors.Errorf("cannot create policy revocation NV counter: %w", err)
		}
	} else {
		f, err := os.Open(dest)
		if err != nil {
			return xerrors.Errorf("cannot open existing key data file to update: %w", err)
		}
		existing, err := readAndIntegrityCheckKeyData(tpm.TPMContext, f, session)
		if err != nil {
			switch e := err.(type) {
			case keyFileError:
				return InvalidKeyFileError{e.err.Error()}
			}
			return xerrors.Errorf("cannot load existing key data file: %w", err)
		}

		pinIndex, err = tpm.WrapHandle(existing.PolicyData.PinIndexHandle)
		if err != nil {
			if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
				return InvalidKeyFileError{fmt.Sprintf("no PIN NV index at handle 0x%08x", existing.PolicyData.PinIndexHandle)}
			}
			return xerrors.Errorf("cannot obtain context for PIN NV index: %w", err)
		}
		if !bytes.Equal(existing.BoundData.PinIndexName, pinIndex.Name()) {
			return InvalidKeyFileError{"the PIN NV index on the TPM doesn't match the original key data file"}
		}
		askForPinHint = existing.AskForPinHint

		policyRevokeIndex, err = tpm.WrapHandle(existing.PolicyData.PolicyRevokeIndexHandle)
		if err != nil {
			if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
				return InvalidKeyFileError{fmt.Sprintf("no policy revocation NV counter at handle 0x%08x",
					existing.PolicyData.PolicyRevokeIndexHandle)}
			}
			return xerrors.Errorf("cannot obtain context for policy revocation NV counter: %w", err)
		}
		if !bytes.Equal(existing.BoundData.PolicyRevokeIndexName, policyRevokeIndex.Name()) {
			return InvalidKeyFileError{"the NV index used for policy revocation on the TPM doesn't match the original " +
				"key data file"}
		}
	}

	// Obtain the revoke count for the new authorization policy
	var nextPolicyRevokeCount uint64
	if c, err := tpm.NVReadCounter(policyRevokeIndex, policyRevokeIndex, session); err != nil {
		return xerrors.Errorf("cannot read revocation counter: %w", err)
	} else {
		nextPolicyRevokeCount = c + 1
	}

	// Compute PCR digests
	var secureBootDigests tpm2.DigestList
	if params != nil {
		secureBootDigests, err = computeSecureBootPolicyDigests(tpm.TPMContext, defaultHashAlgorithm, params)
		if err != nil {
			return fmt.Errorf("cannot compute secure boot policy digests: %v", err)
		}
	} else {
		_, pcrValues, err := tpm.PCRRead(tpm2.PCRSelectionList{
			tpm2.PCRSelection{Hash: defaultHashAlgorithm, Select: tpm2.PCRSelectionData{secureBootPCR}}})
		if err != nil {
			return xerrors.Errorf("cannot read secure boot PCR value: %w", err)
		}
		secureBootDigests = append(secureBootDigests, pcrValues[defaultHashAlgorithm][secureBootPCR])
	}

	// Use the PCR digests and NV index names to generate a single policy digest
	policyComputeIn := policyComputeInput{
		secureBootPCRAlg:     defaultHashAlgorithm,
		grubPCRAlg:           defaultHashAlgorithm,
		snapModelPCRAlg:      defaultHashAlgorithm,
		secureBootPCRDigests: secureBootDigests,
		grubPCRDigests:       tpm2.DigestList{make(tpm2.Digest, 32)},
		snapModelPCRDigests:  tpm2.DigestList{make(tpm2.Digest, 32)},
		pinIndex:             pinIndex,
		policyRevokeIndex:    policyRevokeIndex,
		policyRevokeCount:    nextPolicyRevokeCount}

	policyData, authPolicy, err := computePolicy(defaultHashAlgorithm, &policyComputeIn)
	if err != nil {
		return fmt.Errorf("cannot compute authorization policy: %v", err)
	}

	// Define the template for the sealed key object, using the computed policy digest
	template := tpm2.Public{
		Type:       tpm2.ObjectTypeKeyedHash,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		AuthPolicy: authPolicy,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	sensitive := tpm2.SensitiveCreate{Data: key}

	// Marshal some parameters now to calculate a digest that can be stored in the CreationData returned from the TPM. This
	// allows us to have data that is cryptographically bound to the sealed key object
	boundData := boundKeyData{
		PinIndexName:          pinIndex.Name(),
		PolicyRevokeIndexName: policyRevokeIndex.Name()}
	h := sha256.New()
	// This can't fail
	tpm2.MarshalToWriter(h, boundData)

	// Now create the sealed key object. The command is integrity protected so if the object at the handle we expect the SRK to reside
	// at has a different name (ie, if we're connected via a resource manager and somebody swapped the object with another one), this
	// command will fail. We take advantage of parameter encryption here too.
	priv, pub, creationData, _, creationTicket, err :=
		tpm.Create(srkContext, &sensitive, &template, h.Sum(nil), nil, nil, session.AddAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return xerrors.Errorf("cannot create sealed data object for key: %w", err)
	}

	// Marshal the entire object (sealed key object and auxiliary data) to disk
	data := keyData{
		KeyPrivate:              priv,
		KeyPublic:               pub,
		KeyCreationData:         creationData,
		KeyCreationTicket:       creationTicket,
		AskForPinHint:           askForPinHint,
		PolicyData:              policyData,
		BoundData:               &boundData}

	if err := data.writeToFile(dest); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	if err := tpm.NVIncrement(policyRevokeIndex, policyRevokeIndex, session); err != nil {
		return xerrors.Errorf("cannot revoke old authorization policies: %w", err)
	}

	return nil
}

// DeleteKey takes care of removing a key data file, along with its associated TPM resources. It expects the key data file at the
// path specified to be valid. If the key data file cannot be opened, a wrapped *os.PathError error will be returned. If the file
// contains invalid components, fails any integrity checks, or any associated TPM resources are invalid, a InvalidKeyFileError will
// be returned. In this case, the key data file won't be deleted.
//
// This function requires knowledge of the storage hierarchy authorization value. If an incorrect authorization is provided, a
// AuthFailError error will be returned and the key data file won't be deleted.
//
// This function requires the TPM to be correctly provisioned, else a ErrProvisioningError error will be returned.
func DeleteKey(tpm *TPMConnection, path string, ownerAuth []byte) error {
	session := tpm.HmacSession()
	if ok, err := hasValidSRK(tpm.TPMContext, session); err != nil {
		return err
	} else if !ok {
		return ErrProvisioning
	}

	f, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}

	keyContext, data, err := loadKeyData(tpm.TPMContext, f, session)
	if err != nil {
		switch e := err.(type) {
		case keyFileError:
			return InvalidKeyFileError{e.err.Error()}
		}
		return xerrors.Errorf("cannot load existing key data file: %w", err)
	}
	tpm.FlushContext(keyContext)

	if policyRevokeContext, err := tpm.WrapHandle(data.PolicyData.PolicyRevokeIndexHandle); err == nil {
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, policyRevokeContext, session.WithAuthValue(ownerAuth)); err != nil {
			if isAuthFailError(err) {
				return AuthFailError{tpm2.HandleOwner}
			}
			return xerrors.Errorf("cannot undefine policy revocation NV index: %w", err)
		}
	}

	if pinContext, err := tpm.WrapHandle(data.PolicyData.PinIndexHandle); err == nil {
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, pinContext, session.WithAuthValue(ownerAuth)); err != nil {
			if isAuthFailError(err) {
				return AuthFailError{tpm2.HandleOwner}
			}
			return xerrors.Errorf("cannot undefine NV index for PIN: %w", err)
		}
	}

	if err := os.Remove(path); err != nil {
		return xerrors.Errorf("cannot remove key data file: %w", err)
	}

	return nil
}
