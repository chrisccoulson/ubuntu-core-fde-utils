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
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/snapcore/snapd/snap"

	"golang.org/x/xerrors"
)

const (
	pcrAlgorithm tpm2.HashAlgorithmId = tpm2.HashAlgorithmSHA256
)

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

type OSComponentImage interface {
	fmt.Stringer
	ReadAll() ([]byte, error)
}

type SnapFileOSComponent struct {
	Container snap.Container
	Path      string
	FileName  string
}

func (f SnapFileOSComponent) String() string {
	return f.Path + ":" + f.FileName
}

func (f SnapFileOSComponent) ReadAll() ([]byte, error) {
	return f.Container.ReadFile(f.FileName)
}

type FileOSComponent string

func (p FileOSComponent) String() string {
	return string(p)
}

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

// PolicyParams contains parameters used for computation of the authorization policy for the sealed key object.
type PolicyParams struct {
	// LoadPaths corresponds to alternate trees of OSComponent structures corresponding to the boot sequences
	// that should be permitted to unseal the disk encryption key. The root of each tree must have LoadType
	// set to FirmwareLoad.
	// To support atomic updates of a component (eg, a kernel), SealKeyToTPM should be called before an
	// update is committed with boot sequences containing both the old and new components. If the old and
	// new components are signed with different keys, then this will automatically be reflected in the
	// generated authorization policy. Alternate boot sequences resulting in the same authorization policy
	// are automatically de-duplicated.
	LoadPaths []*OSComponent

	// SecureBootDbKeystores are the source directories for UEFI signature database updates and corresponds to
	// the "--keystore" options passed to sbkeysync when applying updates. To support atomic updates of
	// UEFI signature databases, SealKeyToTPM should be called before the updates contained in these
	// directories are applied by sbkeysync. After applying updates, it should be called again. The ordering
	// of directories here is important - it must match the ordering of directories passed to sbkeysync via
	// the --keystore command by whatever agent is responsible for applying updates. This functionality
	// depends on sbkeysync being available in one of the shell search paths, and assumes that updates are
	// applied with the "--no-default-keystores" option.
	SecureBootDbKeystores []string
}

func computeKeyDynamicAuthPolicy(tpm *tpm2.TPMContext, privateData *privateKeyData, params *PolicyParams, session *tpm2.Session) (*dynamicPolicyData, func(*tpm2.Session) error, error) {
	// Obtain a ResourceContext for the dynamic policy revocation NV index
	policyRevokeIndex, err := tpm.WrapHandle(privateData.PolicyRevokeIndexHandle)
	if err != nil {
		if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
			return nil, nil, InvalidKeyFileError{fmt.Sprintf("no policy revocation NV counter at handle 0x%08x",
				privateData.PolicyRevokeIndexHandle)}
		}
		return nil, nil, xerrors.Errorf("cannot obtain context for policy revocation NV counter: %w", err)
	}
	if !bytes.Equal(privateData.PolicyRevokeIndexName, policyRevokeIndex.Name()) {
		return nil, nil, InvalidKeyFileError{"the NV index used for policy revocation on the TPM doesn't match the original key data file"}
	}

	// Parse the key for signing the dynamic authorization policy
	authKey, err := x509.ParsePKCS1PrivateKey(privateData.AuthorizeKeyPrivate)
	if err != nil {
		return nil, nil, InvalidKeyFileError{fmt.Sprintf("cannot parse dynamic policy authorization key: %v", err)}
	}

	// Obtain the revoke count for the new dynamic authorization policy
	var nextPolicyRevokeCount uint64
	if c, err := tpm.NVReadCounter(policyRevokeIndex, policyRevokeIndex, session); err != nil {
		return nil, nil, xerrors.Errorf("cannot read revocation counter: %w", err)
	} else {
		nextPolicyRevokeCount = c + 1
	}

	// Compute PCR digests
	var secureBootDigests tpm2.DigestList
	var ubuntuBootParamsDigests tpm2.DigestList
	if params != nil {
		secureBootDigests, err = computeSecureBootPolicyDigests(tpm, pcrAlgorithm, params)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot compute secure boot policy digests: %w", err)
		}
		_, pcrValues, err := tpm.PCRRead(tpm2.PCRSelectionList{
			tpm2.PCRSelection{Hash: pcrAlgorithm, Select: tpm2.PCRSelectionData{ubuntuBootParamsPCR}}})
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot read current PCR values: %w", err)
		}
		ubuntuBootParamsDigests = append(ubuntuBootParamsDigests, pcrValues[pcrAlgorithm][ubuntuBootParamsPCR])
	} else {
		_, pcrValues, err := tpm.PCRRead(tpm2.PCRSelectionList{
			tpm2.PCRSelection{Hash: pcrAlgorithm, Select: tpm2.PCRSelectionData{secureBootPCR, ubuntuBootParamsPCR}}})
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot read current PCR values: %w", err)
		}
		secureBootDigests = append(secureBootDigests, pcrValues[pcrAlgorithm][secureBootPCR])
		ubuntuBootParamsDigests = append(ubuntuBootParamsDigests, pcrValues[pcrAlgorithm][ubuntuBootParamsPCR])
	}

	// Use the PCR digests and NV index names to generate a single signed dynamic authorization policy digest
	policyParams := dynamicPolicyComputeParams{
		key:                        authKey,
		secureBootPCRAlg:           pcrAlgorithm,
		ubuntuBootParamsPCRAlg:     pcrAlgorithm,
		secureBootPCRDigests:       secureBootDigests,
		ubuntuBootParamsPCRDigests: ubuntuBootParamsDigests,
		policyRevokeIndex:          policyRevokeIndex,
		policyRevokeCount:          nextPolicyRevokeCount}

	policyData, err := computeDynamicPolicy(sealedKeyNameAlgorithm, &policyParams)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	return policyData, func(session *tpm2.Session) error {
		return tpm.NVIncrement(policyRevokeIndex, policyRevokeIndex, session)
	}, nil
}

type CreationParams struct {
	PolicyRevocationHandle tpm2.Handle
	PinHandle              tpm2.Handle
	OwnerAuth              []byte
}

// SealKeyToTPM seals the provided disk encryption key to the storage hierarchy of the TPM. The caller is required to provide a
// connection to the TPM. The sealed key object and associated metadata that is required during early boot to unlock the encrypted
// volume is written to a file at the path specified by keyDest. Additional data that is required for updating the authorization
// policy is written to a file at the path specified by privateDest. This file must live inside an encrypted volume protected by
// this key.
//
// If the TPM is not correctly provisioned with a persistent storage root key at the expected location, it will return a
// ErrProvisioning error. In this case, ProvisionTPM must be called before proceeding.
//
// The key will be created with an authorization policy based on the current device state. The authorization policy can be updated
// with UpdateKeyAuthPolicy.
//
// If there is already a file at either specified path, a wrapped *os.PathError error will be returned with an underlying error of
// syscall.EEXIST.
//
// The caller is expected to provide handles at which NV indices should be created for policy revocation and PIN support via the
// PolicyRevocationHandle and PinHandle fields of the CreationParams struct. If either handle is already in use, a
// TPMResourceExistsError error will be returned. The handles must be valid NV index handles (MSO == 0x01), and the choice of handle
// should take in to consideration the reserved indices from the "Registry of reserved TPM 2.0 handles and localities" specification.
// It is recommended that the handles are in the block reserved for owner objects (0x01800000 - 0x01bfffff). The owner authorization
// is also required, provided via the OwnerAuth of the CreationParams struct. If the provided owner authorization is incorrect, a
// AuthFailError error will be returned. On a TPM that has been newly provisioned with ProvisionTPM, the owner authorization is empty
// and the nil value can be passed here.
func SealKeyToTPM(tpm *TPMConnection, keyDest, privateDest string, create *CreationParams, policy *PolicyParams, key []byte) error {
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

	succeeded := false

	// Create destination files
	keyFile, err := os.OpenFile(keyDest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return xerrors.Errorf("cannot create key data file: %w", err)
	}
	defer func() {
		keyFile.Close()
		if succeeded {
			return
		}
		os.Remove(keyDest)
	}()

	var privateFile *os.File
	if privateDest != "" {
		var err error
		privateFile, err = os.OpenFile(privateDest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return xerrors.Errorf("cannot create private data file: %w", err)
		}
		defer func() {
			privateFile.Close()
			if succeeded {
				return
			}
			os.Remove(privateDest)
		}()
	}

	// Create NV indices
	pinIndex, err := createPinNvIndex(tpm.TPMContext, create.PinHandle, create.OwnerAuth, session)
	if err != nil {
		switch {
		case isNVIndexDefinedError(err):
			return TPMResourceExistsError{create.PinHandle}
		case isAuthFailError(err):
			return AuthFailError{tpm2.HandleOwner}
		}
		return xerrors.Errorf("cannot create new pin NV index: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm2.HandleOwner, pinIndex, session.WithAuthValue(create.OwnerAuth))
	}()

	policyRevokeIndex, err := createPolicyRevocationNvIndex(tpm.TPMContext, create.PolicyRevocationHandle, create.OwnerAuth, session)
	if err != nil {
		switch {
		case isNVIndexDefinedError(err):
			return TPMResourceExistsError{create.PolicyRevocationHandle}
		case isAuthFailError(err):
			return AuthFailError{tpm2.HandleOwner}
		}
		return xerrors.Errorf("cannot create dynamic authorization policy revocation NV counter: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm2.HandleOwner, policyRevokeIndex, session.WithAuthValue(create.OwnerAuth))
	}()

	// Compute the static policy - this never changes for the lifetime of this key file
	staticPolicyData, authKey, authPolicy, err :=
		computeStaticPolicy(sealedKeyNameAlgorithm, &staticPolicyComputeParams{pinIndex: pinIndex})
	if err != nil {
		return xerrors.Errorf("cannot compute static authorization policy: %w", err)
	}

	// Define the template for the sealed key object, using the computed policy digest
	template := tpm2.Public{
		Type:       tpm2.ObjectTypeKeyedHash,
		NameAlg:    sealedKeyNameAlgorithm,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		AuthPolicy: authPolicy,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	sensitive := tpm2.SensitiveCreate{Data: key}

	// Now create the sealed key object. The command is integrity protected so if the object at the handle we expect the SRK to reside
	// at has a different name (ie, if we're connected via a resource manager and somebody swapped the object with another one), this
	// command will fail. We take advantage of parameter encryption here too.
	priv, pub, _, _, _, err := tpm.Create(srkContext, &sensitive, &template, nil, nil, nil, session.AddAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return xerrors.Errorf("cannot create sealed data object for key: %w", err)
	}

	privateData := privateKeyData{
		AuthorizeKeyPrivate:     x509.MarshalPKCS1PrivateKey(authKey),
		PolicyRevokeIndexHandle: policyRevokeIndex.Handle(),
		PolicyRevokeIndexName:   policyRevokeIndex.Name()}

	// Create a dynamic authorization policy
	dynamicPolicyData, revoke, err := computeKeyDynamicAuthPolicy(tpm.TPMContext, &privateData, policy, session)
	if err != nil {
		return err
	}

	// Marshal the entire object (sealed key object and auxiliary data) to disk
	data := keyData{
		KeyPrivate:        priv,
		KeyPublic:         pub,
		AskForPinHint:     false,
		StaticPolicyData:  staticPolicyData,
		DynamicPolicyData: dynamicPolicyData}

	if err := data.write(keyFile); err != nil {
		return xerrors.Errorf("cannot write key data file: %w", err)
	}

	if privateDest != "" {
		// Marshal the private data to disk
		if err := privateData.write(privateFile); err != nil {
			return xerrors.Errorf("cannot write private data file: %w", err)
		}
	}

	if err := revoke(session); err != nil {
		return xerrors.Errorf("cannot increment dynamic policy revocation NV counter: %w", err)
	}

	succeeded = true
	return nil
}

// UpdateKeyAuthPolicy updates the authorization policy for the sealed key data file at the path specified by the keyPath argument,
// based on the provided params argument. In order to do this, the caller must also specify the path to the private data file that
// was saved by SealKeyToTPM via the privatePath argument. This file should live inside an encrypted volume protected by this key,
// and is required in order to sign the new authorization policy.
//
// If either file cannot be loaded or TPM resources required by the authorization policy do not exist on the TPM, a
// InvalidKeyFileError error will be returned.
//
// On success, the sealed key data file is updated atomically with the new authorization policy.
func UpdateKeyAuthPolicy(tpm *TPMConnection, keyPath, privatePath string, params *PolicyParams) error {
	// Use the HMAC session created when the connection was opened rather than creating a new one.
	session := tpm.HmacSession()

	// Open and read the key data file
	f1, err := os.Open(keyPath)
	if err != nil {
		return xerrors.Errorf("cannot open existing key data file to update: %w", err)
	}
	defer f1.Close()
	data, err := readKeyData(f1)
	if err != nil {
		return InvalidKeyFileError{err.Error()}
	}

	// Open and read the private data file
	f2, err := os.Open(privatePath)
	if err != nil {
		return xerrors.Errorf("cannot open existing private data file: %w", err)
	}
	defer f2.Close()
	privateData, err := readPrivateData(f2)
	if err != nil {
		return InvalidKeyFileError{err.Error()}
	}

	// Compute a new dynamic authorization policy
	policyData, revoke, err := computeKeyDynamicAuthPolicy(tpm.TPMContext, privateData, params, session)
	if err != nil {
		return err
	}

	// Atomically update the key data file
	data.DynamicPolicyData = policyData

	if err := data.writeToFileAtomic(keyPath); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	if err := revoke(session); err != nil {
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

	if policyRevokeContext, err := tpm.WrapHandle(data.DynamicPolicyData.PolicyRevokeIndexHandle); err == nil {
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, policyRevokeContext, session.WithAuthValue(ownerAuth)); err != nil {
			if isAuthFailError(err) {
				return AuthFailError{tpm2.HandleOwner}
			}
			return xerrors.Errorf("cannot undefine policy revocation NV index: %w", err)
		}
	}

	if pinContext, err := tpm.WrapHandle(data.StaticPolicyData.PinIndexHandle); err == nil {
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
