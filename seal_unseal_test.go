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
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func TestCreateAndUnseal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestCreateAndUnseal_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, dest, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, dest)

	f, err := os.Open(dest)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, f, "")
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestCreateDoesntReplace(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestCreateDoesntReplace_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, dest, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, dest)

	fi1, err := os.Stat(dest)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	err = SealKeyToTPM(tpm, dest, &testCreationParams, nil, key)
	if err == nil {
		t.Fatalf("SealKeyToTPM Create should fail if there is already a file with the same path")
	}
	if err != ErrKeyFileExists {
		t.Errorf("Unexpected error: %v", err)
	}

	fi2, err := os.Stat(dest)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	if fi1.ModTime() != fi2.ModTime() {
		t.Errorf("SealKeyToTPM Create modified the existing file")
	}
}

func TestUpdateAndUnseal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUpdateAndUnseal_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, dest, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, dest)

	testPIN := "1234"

	if err := ChangePIN(tpm, dest, "", testPIN); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	fi1, err := os.Stat(dest)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	if err := SealKeyToTPM(tpm, dest, nil, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}

	fi2, err := os.Stat(dest)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	if fi1.ModTime() == fi2.ModTime() {
		t.Errorf("File wasn't updated")
	}

	f, err := os.Open(dest)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, f, testPIN)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestPin(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, nil); err != nil && err != ErrClearRequiresPPI {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	status, err := ProvisionStatus(tpm)
	if err != nil {
		t.Fatalf("Cannot check provision status: %v", err)
	}
	if status&AttrValidSRK == 0 {
		t.Fatalf("No valid SRK for test")
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestPin_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, dest, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, dest)

	testPIN := "1234"

	if err := ChangePIN(tpm, dest, "", testPIN); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	f, err := os.Open(dest)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, f, testPIN)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestRevoke(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestRevoke_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, dest, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, dest)

	f, err := os.Open(dest)
	if err != nil {
		t.Fatalf("Cannot open file: %v", err)
	}
	defer f.Close()

	var keydata bytes.Buffer
	if _, err := io.Copy(&keydata, f); err != nil {
		t.Fatalf("Cannot copy key data file: %v", err)
	}

	if err := SealKeyToTPM(tpm, dest, nil, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}

	_, err = UnsealKeyFromTPM(tpm, &keydata, "")
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
	}
	if err != ErrPolicyRevoked {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUpdateWithoutExisting(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUpdateWithoutExisting_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	err = SealKeyToTPM(tpm, dest, nil, nil, key)
	if err == nil {
		t.Fatalf("SealKeyToTPM Update should fail if there isn't a valid key data file")
	}
	var e *os.PathError
	if !xerrors.As(err, &e) || !os.IsNotExist(e) {
		t.Errorf("Unexpected error: %v", err)
	}

	if _, err := os.Stat(dest); err == nil || !os.IsNotExist(err) {
		t.Errorf("SealKeyToTPM Update should not create a file where there isn't one")
	}
}

func TestPinFail(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, nil); err != nil && err != ErrClearRequiresPPI {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	status, err := ProvisionStatus(tpm)
	if err != nil {
		t.Fatalf("Cannot check provision status: %v", err)
	}
	if status&AttrValidSRK == 0 {
		t.Fatalf("No valid SRK for test")
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestPinFail_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, dest, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, dest)

	testPIN := "1234"

	if err := ChangePIN(tpm, dest, "", testPIN); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	f, err := os.Open(dest)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	_, err = UnsealKeyFromTPM(tpm, f, "")
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
	}
	if err != ErrPinFail {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestPolicyFail(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, nil); err != nil && err != ErrClearRequiresPPI {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	status, err := ProvisionStatus(tpm)
	if err != nil {
		t.Fatalf("Cannot check provision status: %v", err)
	}
	if status&AttrValidSRK == 0 {
		t.Fatalf("No valid SRK for test")
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestPolicyFail_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dest := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, dest, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, dest)

	if _, err := tpm.PCREvent(7, tpm2.Event("foo"), nil); err != nil {
		t.Errorf("PCREvent failed: %v", err)
	}

	f, err := os.Open(dest)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	_, err = UnsealKeyFromTPM(tpm, f, "")
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
	}
	if err != ErrPolicyFail {
		t.Errorf("Unexpected error: %v", err)
	}
}
