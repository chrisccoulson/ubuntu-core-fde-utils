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
	"os"

	"github.com/chrisccoulson/go-tpm2"
)

type SealMode int

const (
	Create SealMode = iota
	Update
)

// SealKeyToTPM seals the provided disk encryption key to the storage hierarchy of a TPM. The caller is required
// to provide a connection to the TPM. The sealed key object and associated metadata (creation data and ticket
// for sealed key object, PIN object and auxiliary policy data) are all written to the file specified by dest. If
// called with mode == Create, a new file will be created and this function will fail if there is already a file
// with the same name. If called with mode == Update, this function expects there to be a valid key data file at
// the location specified by dest. In this case, this function will preserve the PIN object (and therefore the PIN
// object auth value) from the original file, and the original file will be updated atomically.
// TODO: This function prototype will be extended to take policy inputs
func SealKeyToTPM(tpm tpm2.TPMContext, dest string, mode SealMode, key []byte) error {
	// Check that the key is the correct length
	if len(key) != 64 {
		return fmt.Errorf("expected a key length of 512 bits (got %d)", len(key)*8)
	}

	var pinPrivate tpm2.Private
	var pinPublic *tpm2.Public
	var pinFlags uint8

	// If we aren't creating a new key data file, load the PIN from the existing file, else create a new one
	switch mode {
	case Create:
		if _, err := os.Stat(dest); err == nil || !os.IsNotExist(err) {
			return errors.New("cannot create new key data file: file already exists")
		}
		var err error
		pinPrivate, pinPublic, err = createPINObject(tpm)
		if err != nil {
			return fmt.Errorf("cannot create new PIN object: %v", err)
		}
		pinFlags = 0
	case Update:
		f, err := os.Open(dest)
		if err != nil {
			return fmt.Errorf("cannot open existing key data file to update: %v", err)
		}
		var existing keyData
		if _, _, err := existing.loadAndIntegrityCheck(f, tpm, true); err != nil {
			return fmt.Errorf("cannot load existing key data file: %v", err)
		}

		pinPrivate = existing.PinPrivate
		pinPublic = existing.PinPublic
		pinFlags = existing.PinFlags
	}

	// Convert policy inputs in to individual event digests
	//  TODO

	// Use event digests, the event log and GRUB data to generate PCR digests
	//  TODO: Use policy inputs rather than the current PCR values
	//  TODO: Generate digests for other PCRs
	_, digests, err := tpm.PCRRead(tpm2.PCRSelectionList{
		tpm2.PCRSelection{Hash: defaultHashAlgorithm, Select: tpm2.PCRSelectionData{7}}})
	if err != nil {
		return fmt.Errorf("cannot read PCR values: %v", err)
	}

	// Use the PCR digests and PIN object to generate a single policy digest
	pinObjectName, err := pinPublic.Name()
	if err != nil {
		return fmt.Errorf("cannot determine PIN object name: %v", err)
	}

	policyComputeIn := policyComputeInput{
		secureBootPCRAlg:     defaultHashAlgorithm,
		grubPCRAlg:           defaultHashAlgorithm,
		snapModelPCRAlg:      defaultHashAlgorithm,
		secureBootPCRDigests: digests,
		grubPCRDigests:       tpm2.DigestList{make(tpm2.Digest, 32)},
		snapModelPCRDigests:  tpm2.DigestList{make(tpm2.Digest, 32)},
		pinObjectName:        pinObjectName}

	policyData, authPolicy, err := computePolicy(defaultHashAlgorithm, &policyComputeIn)

	// Define the template for the sealed key object, using the calculated policy digest
	template := tpm2.Public{
		Type:       tpm2.AlgorithmKeyedHash,
		NameAlg:    tpm2.AlgorithmSHA256,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		AuthPolicy: authPolicy,
		Params: tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.AlgorithmNull}}}}

	sensitive := tpm2.SensitiveCreate{Data: key}

	// Marshal the auxiliary policy data to calculate a digest that can be stored in the CreationData returned
	// from the TPM. This allows us to have data that is cryptographically bound to the sealed key object
	auxData := auxData{PolicyData: policyData, PinObjectName: pinObjectName}
	auxDataHash := sha256.New()
	if err := tpm2.MarshalToWriter(auxDataHash, auxData); err != nil {
		return fmt.Errorf("cannot marshal auxiliary policy data: %v", err)
	}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	// Create a session for command parameter encryption
	sessionContext, err := tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypeHMAC, &paramEncryptAlg,
		defaultHashAlgorithm, nil)
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

	// Marshal the entire object (sealed key object, creation data, creation ticket, PIN object and auxiliary
	// data) to disk
	data := keyData{
		KeyPrivate:        priv,
		KeyPublic:         pub,
		KeyCreationData:   creationData,
		KeyCreationTicket: creationTicket,
		PinPrivate:        pinPrivate,
		PinPublic:         pinPublic,
		PinFlags:          pinFlags,
		AuxData:           auxData}

	if err := data.writeToFile(dest); err != nil {
		return fmt.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
