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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
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

func computeSealedKeyDynamicAuthPolicy(tpm *tpm2.TPMContext, alg, signAlg tpm2.HashAlgorithmId, authKey *rsa.PrivateKey,
	countIndexPub *tpm2.NVPublic, countIndexAuthPolicies tpm2.DigestList, params *PolicyParams,
	session tpm2.SessionContext) (*dynamicPolicyData, error) {
	// Obtain the count for the new dynamic authorization policy
	nextPolicyCount, err := readDynamicPolicyCounter(tpm, countIndexPub, countIndexAuthPolicies, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot read dynamic policy counter: %w", err)
	}
	nextPolicyCount += 1

	countIndexName, _ := countIndexPub.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of dynamic policy counter: %w", err)
	}

	// Compute PCR digests
	var secureBootDigests tpm2.DigestList
	var ubuntuBootParamsDigests tpm2.DigestList
	if params != nil {
		secureBootDigests, err = computeSecureBootPolicyDigests(tpm, pcrAlgorithm, params)
		if err != nil {
			return nil, xerrors.Errorf("cannot compute secure boot policy digests: %w", err)
		}
		_, pcrValues, err := tpm.PCRRead(tpm2.PCRSelectionList{
			tpm2.PCRSelection{Hash: pcrAlgorithm, Select: tpm2.PCRSelectionData{ubuntuBootParamsPCR}}})
		if err != nil {
			return nil, xerrors.Errorf("cannot read current PCR values: %w", err)
		}
		ubuntuBootParamsDigests = append(ubuntuBootParamsDigests, pcrValues[pcrAlgorithm][ubuntuBootParamsPCR])
	} else {
		_, pcrValues, err := tpm.PCRRead(tpm2.PCRSelectionList{
			tpm2.PCRSelection{Hash: pcrAlgorithm, Select: tpm2.PCRSelectionData{secureBootPCR, ubuntuBootParamsPCR}}})
		if err != nil {
			return nil, xerrors.Errorf("cannot read current PCR values: %w", err)
		}
		secureBootDigests = append(secureBootDigests, pcrValues[pcrAlgorithm][secureBootPCR])
		ubuntuBootParamsDigests = append(ubuntuBootParamsDigests, pcrValues[pcrAlgorithm][ubuntuBootParamsPCR])
	}

	// Use the PCR digests and NV index names to generate a single signed dynamic authorization policy digest
	policyParams := dynamicPolicyComputeParams{
		key:                        authKey,
		signAlg:                    signAlg,
		secureBootPCRAlg:           pcrAlgorithm,
		ubuntuBootParamsPCRAlg:     pcrAlgorithm,
		secureBootPCRDigests:       secureBootDigests,
		ubuntuBootParamsPCRDigests: ubuntuBootParamsDigests,
		policyCountIndexName:       countIndexName,
		policyCount:                nextPolicyCount}

	policyData, err := computeDynamicPolicy(alg, &policyParams)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	return policyData, nil
}

type CreationParams struct {
	PinHandle tpm2.Handle
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
// If policy is nil, the key will be created with an authorization policy based on the current device state. The authorization policy
// can be updated afterwards with UpdateKeyAuthPolicy. If policy is provided, the authorization policy will be computed based on
// the provided parameters.
//
// If there is already a file at either specified path, a wrapped *os.PathError error will be returned with an underlying error of
// syscall.EEXIST.
//
// The caller is expected to provide a handle at which a NV index should be created for dynamic authorization policy revocation and
// PIN support via the PinHandle field of the CreationParams struct. If the handle is already in use, a TPMResourceExistsError error
// will be returned. The handle must be a valid NV index handle (MSO == 0x01), and the choice of handle should take in to
// consideration the reserved indices from the "Registry of reserved TPM 2.0 handles and localities" specification. It is recommended
// that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff). The owner authorization is also required,
// provided by calling TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided owner
// authorization is incorrect, a AuthFailError error will be returned. On a TPM that has been newly provisioned with ProvisionTPM,
// the owner authorization is empty and the nil value can be passed here.
func SealKeyToTPM(tpm *TPMConnection, keyDest, privateDest string, create *CreationParams, policy *PolicyParams, key []byte) error {
	// Check that the key is the correct length
	if len(key) != 32 {
		return fmt.Errorf("expected a key length of 256 bits (got %d)", len(key)*8)
	}

	// Use the HMAC session created when the connection was opened rather than creating a new one.
	session := tpm.HmacSession()

	// Obtain a context for the SRK now. If we're called immediately after ProvisionTPM without closing the TPMConnection, we
	// use the context cached by ProvisionTPM, which corresponds to the object provisioned. If not, the public area is read back
	// from the TPM and some sanity checks are performed to make sure it looks like a SRK. Note that if this succeeds, it doesn't
	// guarantee that the returned context corresponds to an object created with the same template that ProvisionTPM uses, and doesn't
	// guarantee that a future call to ProvisionTPM wouldn't produce a different key.
	srkContext := tpm.provisionedSrkContext
	if srkContext == nil {
		var err error
		srkContext, err = tpm.CreateResourceContextFromTPM(srkHandle)
		if err != nil {
			if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
				return ErrProvisioning
			}
			return xerrors.Errorf("cannot create context for SRK: %w", err)
		}
		if ok, err := isObjectPrimaryKeyWithTemplate(tpm.TPMContext, tpm.OwnerHandleContext(), srkContext, &srkTemplate, session); err != nil {
			return xerrors.Errorf("cannot determine if object at SRK handle is a primary key in the storage hierarchy: %w", err)
		} else if !ok {
			return ErrProvisioning
		}
	}

	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
			return ErrProvisioning
		}
		return xerrors.Errorf("cannot create context for lock NV index: %w", err)
	}
	lockIndexPub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, lockIndex, session)
	if err != nil {
		return xerrors.Errorf("cannot determine if NV index is global lock index: %w", err)
	} else if lockIndexPub == nil {
		return ErrProvisioning
	}
	lockIndexName, err := lockIndexPub.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of global lock NV index: %w", err)
	}

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

	// Create an asymmetric key for signing authorization policy updates, and authorizing dynamic auhtorization
	// policy revocations.
	authKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return xerrors.Errorf("cannot generate RSA key pair for signing dynamic authorization policies: %w", err)
	}

	// Create pin NV index
	pinIndexPub, pinIndexAuthPolicies, err := createPinNvIndex(tpm.TPMContext, create.PinHandle, &authKey.PublicKey, session)
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
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
		if err != nil {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, session)
	}()

	sealedKeyNameAlg := tpm2.HashAlgorithmSHA256

	// Compute the static policy - this never changes for the lifetime of this key file
	staticPolicyData, authPolicy, err := computeStaticPolicy(sealedKeyNameAlg, &staticPolicyComputeParams{
		key:                  &authKey.PublicKey,
		pinIndexPub:          pinIndexPub,
		pinIndexAuthPolicies: pinIndexAuthPolicies,
		lockIndexName:        lockIndexName})
	if err != nil {
		return xerrors.Errorf("cannot compute static authorization policy: %w", err)
	}

	// Define the template for the sealed key object, using the computed policy digest
	template := tpm2.Public{
		Type:       tpm2.ObjectTypeKeyedHash,
		NameAlg:    sealedKeyNameAlg,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		AuthPolicy: authPolicy,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	sensitive := tpm2.SensitiveCreate{Data: key}

	// Have the digest of the private data recorded in the creation data for the sealed data object.
	var privateData privateKeyData
	privateData.Data.AuthorizeKeyPrivate = x509.MarshalPKCS1PrivateKey(authKey)

	h := crypto.SHA256.New()
	if err := tpm2.MarshalToWriter(h, &privateData.Data); err != nil {
		panic(fmt.Sprintf("cannot marshal private data: %v", err))
	}

	// Now create the sealed key object. The command is integrity protected so if the object at the handle we expect the SRK to reside
	// at has a different name (ie, if we're connected via a resource manager and somebody swapped the object with another one), this
	// command will fail. We take advantage of parameter encryption here too.
	priv, pub, creationData, _, creationTicket, err :=
		tpm.Create(srkContext, &sensitive, &template, h.Sum(nil), nil, session.IncludeAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return xerrors.Errorf("cannot create sealed data object for key: %w", err)
	}

	privateData.CreationData = creationData
	privateData.CreationTicket = creationTicket

	// Create a dynamic authorization policy
	dynamicPolicyData, err :=
		computeSealedKeyDynamicAuthPolicy(tpm.TPMContext, sealedKeyNameAlg, staticPolicyData.AuthorizeKeyPublic.NameAlg, authKey,
			pinIndexPub, pinIndexAuthPolicies, policy, session)
	if err != nil {
		return err
	}

	// Marshal the entire object (sealed key object and auxiliary data) to disk
	data := keyData{
		KeyPrivate:        priv,
		KeyPublic:         pub,
		AuthModeHint:      AuthModeNone,
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

	if err := incrementDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, authKey,
		data.StaticPolicyData.AuthorizeKeyPublic, session); err != nil {
		return xerrors.Errorf("cannot increment dynamic policy counter: %w", err)
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

	// Open the key data file
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer keyFile.Close()

	// Open the private data file
	privateFile, err := os.Open(privatePath)
	if err != nil {
		return xerrors.Errorf("cannot open private data file: %w", err)
	}
	defer privateFile.Close()

	data, privateData, pinIndexPublic, err := readAndValidateKeyData(tpm.TPMContext, keyFile, privateFile, session)
	if err != nil {
		var kfErr keyFileError
		if xerrors.As(err, &kfErr) {
			return InvalidKeyFileError{err.Error()}
		}
		// FIXME: Turn the missing lock NV index in to ErrProvisioning
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}

	authKey, err := x509.ParsePKCS1PrivateKey(privateData.Data.AuthorizeKeyPrivate)
	if err != nil {
		return xerrors.Errorf("cannot parse authorization key: %w", err)
	}

	// Compute a new dynamic authorization policy
	policyData, err :=
		computeSealedKeyDynamicAuthPolicy(tpm.TPMContext, data.KeyPublic.NameAlg, data.StaticPolicyData.AuthorizeKeyPublic.NameAlg, authKey,
			pinIndexPublic, data.StaticPolicyData.PinIndexAuthPolicies, params, session)
	if err != nil {
		return err
	}

	// Atomically update the key data file
	data.DynamicPolicyData = policyData

	if err := data.writeToFileAtomic(keyPath); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	if err := incrementDynamicPolicyCounter(tpm.TPMContext, pinIndexPublic, data.StaticPolicyData.PinIndexAuthPolicies, authKey,
		data.StaticPolicyData.AuthorizeKeyPublic, session); err != nil {
		return xerrors.Errorf("cannot revoke old dynamic authorization policies: %w", err)
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
func DeleteKey(tpm *TPMConnection, path string) error {
	session := tpm.HmacSession()

	f, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}

	data, err := readKeyData(f)
	if err != nil {
		return InvalidKeyFileError{err.Error()}
	}

	keyContext, err := data.load(tpm.TPMContext, session)
	if err != nil {
		var kfErr keyFileError
		var ruErr tpm2.ResourceUnavailableError
		switch {
		case xerrors.As(err, &kfErr):
			return InvalidKeyFileError{kfErr.err.Error()}
		case xerrors.As(err, &ruErr):
			return ErrProvisioning
		}
		return xerrors.Errorf("cannot load existing key data file: %w", err)
	}
	tpm.FlushContext(keyContext)

	if pinContext, err := tpm.CreateResourceContextFromTPM(data.StaticPolicyData.PinIndexHandle); err == nil {
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), pinContext, session); err != nil {
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
