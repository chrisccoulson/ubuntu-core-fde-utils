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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/snapcore/snapd/snap"
)

const (
	pcrAlgorithm tpm2.AlgorithmId = tpm2.AlgorithmSHA256
)

type SealMode int

const (
	Create SealMode = iota
	Update
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

// SealKeyToTPM seals the provided disk encryption key to the storage hierarchy of a TPM. The caller is required
// to provide a connection to the TPM. The sealed key object and associated metadata (creation data and ticket
// for sealed key object, PIN data and auxiliary policy data) are all written to the file specified by dest.
//
// If called with mode == Create, a new file will be created and this function will fail if there is already a file
// with the same name. When called with mode == Create, the caller is also expected to provide handles at which
// NV indices should be created for policy revocation and PIN support via the policyRevocationHandle and pinHandle
// parameters. If either handle is already in use, an error will be returned. The handles must be valid NV index
// handles (MSO == 0x01), and the choice of handle should take in to consideration the reserved indices from the
// "Registry of reserved TPM 2.0 handles and localities" specification. It is recommended that the handles are in
// the block reserved for owner objects (0x01800000 - 0x01bfffff). When called with mode == Create, the owner
// authorization is required, provided via ownerAuth. On a TPM that has been newly provisioned with ProvisionTPM,
// the owner authorization is empty and the nil value can be passed here.
//
// If called with mode == Update, this function expects there to be a valid key data file at the location
// specified by dest, and it expects NV indices associated with the key data file to be present. In this case,
// this function will preserve the PIN object (and therefore the PIN object auth value) from the original file,
// and the original file will be updated atomically.
//
// The authorization policy for sealed key object will be computed based on params.
func SealKeyToTPM(tpm *tpm2.TPMContext, mode SealMode, dest string, policyRevocationHandle, pinHandle tpm2.Handle,
	params *SealParams, key []byte, ownerAuth interface{}) error {
	// Check that the key is the correct length
	if len(key) != 64 {
		return fmt.Errorf("expected a key length of 512 bits (got %d)", len(key)*8)
	}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	var pinIndexContext tpm2.ResourceContext
	var pinIndexName tpm2.Name
	var pinIndexPolicies tpm2.DigestList
	var askForPinHint bool

	var policyRevokeIndexContext tpm2.ResourceContext
	var policyRevokeIndexName tpm2.Name

	// If we are creating a new sealed key object, create the associated NV indices
	switch mode {
	case Create:
		if _, err := os.Stat(dest); err == nil || !os.IsNotExist(err) {
			return errors.New("cannot create new key data file: file already exists")
		}

		pinIndexContext, pinIndexPolicies, err = createPinNvIndex(tpm, pinHandle, ownerAuth)
		if err != nil {
			return fmt.Errorf("cannot create new pin NV index: %v", err)
		}
		pinIndexName = pinIndexContext.Name()

		policyRevokeIndexContext, err =
			createPolicyRevocationNvIndex(tpm, policyRevocationHandle, ownerAuth)
		if err != nil {
			return fmt.Errorf("cannot create revocation counter: %v", err)
		}
		policyRevokeIndexName = policyRevokeIndexContext.Name()
	case Update:
		f, err := os.Open(dest)
		if err != nil {
			return fmt.Errorf("cannot open existing key data file to update: %v", err)
		}
		var existing keyData
		if _, err := existing.loadAndIntegrityCheck(f, tpm, true); err != nil {
			return fmt.Errorf("cannot load existing key data file: %v", err)
		}

		pinIndexContext, err = tpm.WrapHandle(existing.AuxData.PolicyData.PinIndexHandle)
		if err != nil {
			return fmt.Errorf("cannot create context for PIN index: %v", err)
		}
		pinIndexPolicies = existing.AuxData.PinIndexPolicyORDigests
		pinIndexName = existing.AuxData.PinIndexName
		askForPinHint = existing.AskForPinHint

		policyRevokeIndexContext, err = tpm.WrapHandle(existing.AuxData.PolicyData.PolicyRevokeIndexHandle)
		if err != nil {
			return fmt.Errorf("cannot create context for revocation counter: %v", err)
		}
		policyRevokeIndexName = existing.AuxData.PolicyRevokeIndexName
	}

	var nextPolicyRevokeCount uint64
	if c, err := tpm.NVReadCounter(policyRevokeIndexContext, policyRevokeIndexContext, nil); err != nil {
		return fmt.Errorf("cannot read revocation counter: %v", err)
	} else {
		nextPolicyRevokeCount = c + 1
	}

	// Compute PCR digests
	var secureBootDigests tpm2.DigestList
	if params != nil {
		secureBootDigests, err = computeSecureBootPolicyDigests(tpm, pcrAlgorithm, params)
		if err != nil {
			return fmt.Errorf("cannot compute secure boot policy digests: %v", err)
		}
	} else {
		_, secureBootDigests, err = tpm.PCRRead(tpm2.PCRSelectionList{
			tpm2.PCRSelection{Hash: pcrAlgorithm,
				Select: tpm2.PCRSelectionData{secureBootPCR}}})
		if err != nil {
			return fmt.Errorf("cannot read secure boot PCR value: %v", err)
		}
	}

	// Use the PCR digests and NV index names to generate a single policy digest
	policyComputeIn := policyComputeInput{
		secureBootPCRAlg:        pcrAlgorithm,
		grubPCRAlg:              pcrAlgorithm,
		snapModelPCRAlg:         pcrAlgorithm,
		secureBootPCRDigests:    secureBootDigests,
		grubPCRDigests:          tpm2.DigestList{make(tpm2.Digest, 32)},
		snapModelPCRDigests:     tpm2.DigestList{make(tpm2.Digest, 32)},
		pinIndexHandle:          pinIndexContext.Handle(),
		pinIndexName:            pinIndexName,
		policyRevokeIndexHandle: policyRevokeIndexContext.Handle(),
		policyRevokeIndexName:   policyRevokeIndexName,
		policyRevokeCount:       nextPolicyRevokeCount}

	policyData, authPolicy, err := computePolicy(sealedKeyNameAlgorithm, &policyComputeIn)

	// Define the template for the sealed key object, using the calculated policy digest
	template := tpm2.Public{
		Type:       tpm2.AlgorithmKeyedHash,
		NameAlg:    sealedKeyNameAlgorithm,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		AuthPolicy: authPolicy,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.AlgorithmNull}}}}
	sensitive := tpm2.SensitiveCreate{Data: key}

	// Marshal the auxiliary policy data to calculate a digest that can be stored in the CreationData returned
	// from the TPM. This allows us to have data that is cryptographically bound to the sealed key object
	auxData := auxData{PolicyData: policyData,
		PinIndexName:            pinIndexName,
		PinIndexPolicyORDigests: pinIndexPolicies,
		PolicyRevokeIndexName:   policyRevokeIndexName}
	auxDataHash := sha256.New()
	if err := tpm2.MarshalToWriter(auxDataHash, auxData); err != nil {
		return fmt.Errorf("cannot marshal auxiliary policy data: %v", err)
	}

	// Create a session for command parameter encryption
	sessionContext, err := tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypeHMAC, &paramEncryptAlg,
		defaultSessionHashAlgorithm, nil)
	if err != nil {
		return fmt.Errorf("cannot create session for encryption: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	// Now create the sealed key object
	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrCommandEncrypt}
	priv, pub, creationData, _, creationTicket, err :=
		tpm.Create(srkContext, &sensitive, &template, auxDataHash.Sum(nil), nil, nil, &session)
	if err != nil {
		return fmt.Errorf("cannot create sealed data object for key: %v", err)
	}

	// Marshal the entire object (sealed key object, creation data, creation ticket and auxiliarya data) to
	// disk
	data := keyData{
		KeyPrivate:        priv,
		KeyPublic:         pub,
		KeyCreationData:   creationData,
		KeyCreationTicket: creationTicket,
		AskForPinHint:     askForPinHint,
		AuxData:           auxData}

	if err := data.writeToFile(dest); err != nil {
		return fmt.Errorf("cannot write key data file: %v", err)
	}

	if err := tpm.NVIncrement(policyRevokeIndexContext, policyRevokeIndexContext, nil); err != nil {
		return fmt.Errorf("cannot revoke old authorization policies: %v", err)
	}

	return nil
}

func DeleteKey(tpm *tpm2.TPMContext, path string, ownerAuth interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open key data file: %v", err)
	}

	var data keyData
	if _, err := data.loadAndIntegrityCheck(f, tpm, true); err != nil {
		return fmt.Errorf("cannot load key data file: %v", err)
	}

	policyRevokeContext, err := tpm.WrapHandle(data.AuxData.PolicyData.PolicyRevokeIndexHandle)
	if err == nil {
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, policyRevokeContext, ownerAuth); err != nil {
			return fmt.Errorf("cannot undefine policy revocation NV index: %v", err)
		}
	}
	pinContext, err := tpm.WrapHandle(data.AuxData.PolicyData.PinIndexHandle)
	if err == nil {
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, pinContext, ownerAuth); err != nil {
			return fmt.Errorf("cannot undefine NV index for PIN: %v", err)
		}
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("cannot remove key data file: %v", err)
	}

	return nil
}
