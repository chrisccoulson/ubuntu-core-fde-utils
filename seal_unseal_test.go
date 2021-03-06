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
	"reflect"
	"syscall"
	"testing"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func TestCreateAndUnseal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestCreateAndUnseal_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	k, err := LoadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	keyUnsealed, err := k.UnsealFromTPM(tpm, "", false)
	if err != nil {
		t.Fatalf("UnsealFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestCreateDoesntReplace(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestCreateDoesntReplace_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"
	privFile := tmpDir + "/keypriv"

	if err := SealKeyToTPM(tpm, keyFile, privFile, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	kfi1, err := os.Stat(keyFile)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}
	pfi1, err := os.Stat(privFile)
	if err != nil {
		t.Errorf("Cannot stat private data file: %v", err)
	}

	err = SealKeyToTPM(tpm, keyFile, privFile, &testCreationParams, nil, key)
	if err == nil {
		t.Fatalf("SealKeyToTPM Create should fail if there is already a file with the same path")
	}
	var e *os.PathError
	if !xerrors.As(err, &e) || e.Err != syscall.EEXIST || e.Path != keyFile {
		t.Errorf("Unexpected error: %v", err)
	}

	kfi2, err := os.Stat(keyFile)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	if kfi1.ModTime() != kfi2.ModTime() {
		t.Errorf("SealKeyToTPM Create modified the existing file")
	}

	keyFile2 := tmpDir + "/keydata2"

	err = SealKeyToTPM(tpm, keyFile2, privFile, &testCreationParams, nil, key)
	if err == nil {
		t.Fatalf("SealKeyToTPM Create should fail if there is already a file with the same path")
	}
	if !xerrors.As(err, &e) || e.Err != syscall.EEXIST || e.Path != privFile {
		t.Errorf("Unexpected error: %v", err)
	}

	pfi2, err := os.Stat(privFile)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	if pfi1.ModTime() != pfi2.ModTime() {
		t.Errorf("SealKeyToTPM Create modified the existing file")
	}
}

func TestUpdateAndUnseal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUpdateAndUnseal_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"
	privFile := tmpDir + "/keypriv"

	if err := SealKeyToTPM(tpm, keyFile, privFile, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	testPIN := "1234"

	if err := ChangePIN(tpm, keyFile, "", testPIN); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	fi1, err := os.Stat(keyFile)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	if err := UpdateKeyAuthPolicy(tpm, keyFile, privFile, nil); err != nil {
		t.Fatalf("UpdateKeyAuthPolicy failed: %v", err)
	}

	fi2, err := os.Stat(keyFile)
	if err != nil {
		t.Errorf("Cannot stat key data file: %v", err)
	}

	if fi1.ModTime() == fi2.ModTime() {
		t.Errorf("File wasn't updated")
	}

	k, err := LoadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	keyUnsealed, err := k.UnsealFromTPM(tpm, testPIN, false)
	if err != nil {
		t.Fatalf("UnsealFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestUnsealWithPin(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUnsealWithPin_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keyfile"

	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	testPIN := "1234"

	if err := ChangePIN(tpm, keyFile, "", testPIN); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	k, err := LoadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	keyUnsealed, err := k.UnsealFromTPM(tpm, testPIN, false)
	if err != nil {
		t.Fatalf("UnsealFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestUnsealRevoked(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUnsealRevoked_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"
	keyFile2 := tmpDir + "/keydata.old"
	privFile := tmpDir + "/keypriv"

	if err := SealKeyToTPM(tpm, keyFile, privFile, &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	f1, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Cannot open file: %v", err)
	}
	defer f1.Close()

	f2, err := os.OpenFile(keyFile2, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("Cannot open file: %v", err)
	}
	defer f2.Close()

	if _, err := io.Copy(f2, f1); err != nil {
		t.Fatalf("Cannot copy key data file: %v", err)
	}

	if err := UpdateKeyAuthPolicy(tpm, keyFile, privFile, nil); err != nil {
		t.Fatalf("UpdateKeyAuthPolicy failed: %v", err)
	}

	k, err := LoadSealedKeyObject(keyFile2)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	_, err = k.UnsealFromTPM(tpm, "", false)
	if err == nil {
		t.Fatalf("UnsealFromTPM should have failed")
	}

	if _, ok := err.(InvalidKeyFileError); !ok || err.Error() != "invalid key data file: encountered an error whilst executing the "+
		"authorization policy assertions: dynamic authorization policy revocation check failed: TPM returned an error whilst executing "+
		"command TPM_CC_PolicyNV: TPM_RC_POLICY (policy failure in math operation or an invalid authPolicy value)" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUnsealWithWrongPin(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUnsealWithWrongPin_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	testPIN := "1234"

	if err := ChangePIN(tpm, keyFile, "", testPIN); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	k, err := LoadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	_, err = k.UnsealFromTPM(tpm, "", false)
	if err == nil {
		t.Fatalf("UnsealFromTPM should have failed")
	}
	if err != ErrPinFail {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUnsealPolicyFail(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUnsealPolicyFail_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), tpm2.Event("foo"), nil); err != nil {
		t.Errorf("PCREvent failed: %v", err)
	}

	k, err := LoadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	_, err = k.UnsealFromTPM(tpm, "", false)
	if err == nil {
		t.Fatalf("UnsealFromTPM should have failed")
	}

	if _, ok := err.(InvalidKeyFileError); !ok || err.Error() != "invalid key data file: encountered an error whilst executing the "+
		"authorization policy assertions: cannot execute PCR assertions: cannot execute PolicyOR assertion after PolicyPCR assertion "+
		"against PCR7: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyOR: TPM_RC_VALUE (value is out of "+
		"range or is not correct for the context)" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUnsealLockout(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUnsealLockout_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	// Put the TPM in DA lockout mode
	if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), 0, 7200, 86400, nil); err != nil {
		t.Errorf("DictionaryAttackParameters failed: %v", err)
	}
	defer func() {
		if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), 32, 7200, 86400, nil); err != nil {
			t.Errorf("DictionaryAttackParameters failed: %v", err)
		}
		if err := tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), nil); err != nil {
			t.Errorf("DictionaryAttackLockReset failed: %v", err)
		}
	}()

	k, err := LoadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	_, err = k.UnsealFromTPM(tpm, "", false)
	if err == nil {
		t.Fatalf("UnsealFromTPM should have failed")
	}
	if err != ErrLockout {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestSealWithProvisioningError(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestSealWithProvisioningError_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	prepare := func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
			t.Fatalf("Failed to provision TPM for test: %v", err)
		}
	}

	run := func(t *testing.T, tpm *TPMConnection) {
		err = SealKeyToTPM(tpm, keyFile, "", &testCreationParams, nil, key)
		if err == nil {
			t.Fatalf("SealKeyToTPM should have failed")
		}
		if err != ErrProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	}

	t.Run("NoSRK", func(t *testing.T) {
		prepare(t)
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		srkContext, err := tpm.CreateResourceContextFromTPM(srkHandle)
		if err != nil {
			t.Fatalf("No SRK context: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		run(t, tpm)
	})

	t.Run("InvalidSRK", func(t *testing.T) {
		prepare(t)
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		srkContext, err := tpm.CreateResourceContextFromTPM(srkHandle)
		if err != nil {
			t.Fatalf("No SRK context: %v", err)
		}
		priv, pub, _, _, _, err := tpm.Create(srkContext, nil, &srkTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		fakeSrkContext, err := tpm.Load(srkContext, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, fakeSrkContext)

		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), fakeSrkContext, srkHandle, nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}

		run(t, tpm)
	})
}

func TestUnsealProvisioningError(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	prepare := func(t *testing.T) {
		if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
			t.Fatalf("Failed to provision TPM for test: %v", err)
		}
	}
	prepare(t)

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUnsealProvisioningError_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, nil, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer func() {
		if err := os.Remove(keyFile); err != nil {
			t.Errorf("Remove failed: %v", err)
		}
		pinContext, err := tpm.CreateResourceContextFromTPM(testCreationParams.PinHandle)
		if err != nil {
			t.Errorf("No PIN NV index: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), pinContext, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	run := func(t *testing.T) {
		k, err := LoadSealedKeyObject(keyFile)
		if err != nil {
			t.Fatalf("LoadSealedKeyObject failed: %v", err)
		}

		_, err = k.UnsealFromTPM(tpm, "", false)
		if err == nil {
			t.Fatalf("UnsealFromTPM should have failed")
		}
		if err != ErrProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	}

	t.Run("NoSRK", func(t *testing.T) {
		prepare(t)
		srkContext, err := tpm.CreateResourceContextFromTPM(srkHandle)
		if err != nil {
			t.Fatalf("No SRK context: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		run(t)
	})

	t.Run("InvalidSRK", func(t *testing.T) {
		prepare(t)
		srkContext, err := tpm.CreateResourceContextFromTPM(srkHandle)
		if err != nil {
			t.Fatalf("No SRK context: %v", err)
		}
		priv, pub, _, _, _, err := tpm.Create(srkContext, nil, &srkTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		fakeSrkContext, err := tpm.Load(srkContext, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, fakeSrkContext)

		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), fakeSrkContext, srkHandle, nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}

		run(t)
	})
}

func TestLockAccessAfterUnseal(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	defer func() {
		eventLogPathForTesting = ""
		efivarsPathForTesting = ""
	}()

	resetTPMSimulator(t, tpm, tcti)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	eventLog := "testdata/eventlog3.bin"
	eventLogPathForTesting = eventLog
	efivarsPathForTesting = "testdata/efivars1"
	cmdline := "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run"

	replayLogToTPM(t, tpm, tcti, eventLog)
	replayBootParamsToTPM(t, tpm, cmdline)

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestLockAccessAfterUnseal_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	params := PolicyParams{
		LoadPaths: []*OSComponent{
			&OSComponent{
				LoadType: FirmwareLoad,
				Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
				Next: []*OSComponent{
					&OSComponent{
						LoadType: DirectLoadWithShimVerify,
						Image:    FileOSComponent("testdata/mock.efi.signed.2"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}},
		KernelCommandlines: []string{cmdline}}
	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, &params, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	k, err := LoadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("LoadSealedKeyObject failed: %v", err)
	}

	keyUnsealed, err := k.UnsealFromTPM(tpm, "", true)
	if err != nil {
		t.Fatalf("UnsealFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}

	_, err = k.UnsealFromTPM(tpm, "", true)
	if err == nil {
		t.Fatalf("UnsealFromTPM should have failed")
	}
	if _, ok := err.(InvalidKeyFileError); !ok || err.Error() != "invalid key data file: encountered an error whilst executing the "+
		"authorization policy assertions: policy lock check failed: TPM returned an error whilst executing command TPM_CC_PolicyNV: "+
		"TPM_RC_NV_LOCKED (NV access locked)" {
		t.Errorf("Unexpected error: %v", err)
	}

	resetTPMSimulator(t, tpm, tcti)
	replayLogToTPM(t, tpm, tcti, eventLog)
	replayBootParamsToTPM(t, tpm, cmdline)

	keyUnsealed, err = k.UnsealFromTPM(tpm, "", true)
	if err != nil {
		t.Fatalf("UnsealFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestCreateAndUnsealWithParams(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	defer func() {
		eventLogPathForTesting = ""
		efivarsPathForTesting = ""
	}()

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	for _, data := range []struct {
		desc            string
		creationLogPath string
		trustedLogPath  string
		efivars         string
		cmdline		string
		params          *PolicyParams
		err             string
		errType         reflect.Type
	}{
		{
			// Test sealing and unsealing with a classic layout
			desc:            "Classic",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog3.bin",
			efivars:         "testdata/efivars1",
			cmdline:	 "BOOT_IMAGE=/vmlinuz-5.3.0-28-generic root=/dev/mapper/vgubuntu-root ro quiet splash mem_sleep_default=deep vt.handoff=7",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.2"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}},
				KernelCommandlines: []string{
					"BOOT_IMAGE=/vmlinuz-5.3.0-28-generic root=/dev/mapper/vgubuntu-root ro quiet splash mem_sleep_default=deep vt.handoff=7",
					"BOOT_IMAGE=/vmlinuz-5.3.0-27-generic root=/dev/mapper/vgubuntu-root ro quiet splash mem_sleep_default=deep vt.handoff=7",
					"BOOT_IMAGE=/vmlinuz-5.3.0-26-generic root=/dev/mapper/vgubuntu-root ro quiet splash mem_sleep_default=deep vt.handoff=7"}},
		},
		{
			// Test sealing and unsealing with a UC20 style layout
			desc:            "UC20",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog4.bin",
			efivars:         "testdata/efivars1",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
		},
		{
			// Test sealing and unsealing with a UC20 style layout and booting in to an alternate mode
			desc:            "UC20",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog4.bin",
			efivars:         "testdata/efivars1",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
		},
		{
			// Test sealing before upgrading to a kernel signed with a new key, and then unsealing with the old kernel
			desc:            "UC20KernelKeyRotationUnsealPreUpgrade",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog5.bin",
			efivars:         "testdata/efivars2",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.2")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")},
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
		},
		{
			// Test sealing before upgrading to a kernel signed with a new key, and then unsealing post-upgrade with the new kernel
			desc:            "UC20KernelKeyRotationUnsealPostUpgrade",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog6.bin",
			efivars:         "testdata/efivars2",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.2")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")},
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
		},
		{
			// Test sealing before applying a UEFI signature DB update and then unsealing before the update is applied
			desc:            "DbUpdateUnsealPreUpdate",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog4.bin",
			efivars:         "testdata/efivars1",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}},
				SecureBootDbKeystores: []string{"testdata/updates1"},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
		},
		{
			// Test sealing before applying a UEFI signature DB update and then unsealing post-update
			desc:            "DbUpdateUnsealPostUpdate",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog5.bin",
			efivars:         "testdata/efivars1",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}},
				SecureBootDbKeystores: []string{"testdata/updates1"},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
		},
		{
			desc:            "PolicyFailSecureBoot",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog5.bin",
			efivars:         "testdata/efivars2",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.2")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
			err: "invalid key data file: encountered an error whilst executing the authorization policy assertions: cannot execute PCR " +
				"assertions: cannot execute PolicyOR assertion after PolicyPCR assertion against PCR7: TPM returned an error for parameter 1 " +
				"whilst executing command TPM_CC_PolicyOR: TPM_RC_VALUE (value is out of range or is not correct for the context)",
			errType: reflect.TypeOf(InvalidKeyFileError{}),
		},
		{
			desc:            "PolicyFailCommandline",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog4.bin",
			efivars:         "testdata/efivars1",
			cmdline:	 "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run init=/bin/sh",
			params: &PolicyParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim2.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}},
				KernelCommandlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}},
			err: "invalid key data file: encountered an error whilst executing the authorization policy assertions: cannot execute PCR " +
				"assertions: cannot execute PolicyOR assertion after PolicyPCR assertion against PCR12: TPM returned an error for parameter 1 " +
				"whilst executing command TPM_CC_PolicyOR: TPM_RC_VALUE (value is out of range or is not correct for the context)",
			errType: reflect.TypeOf(InvalidKeyFileError{}),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			resetTPMSimulator(t, tpm, tcti)
			replayLogToTPM(t, tpm, tcti, data.creationLogPath)

			eventLogPathForTesting = data.creationLogPath
			efivarsPathForTesting = data.efivars

			key := make([]byte, 32)
			rand.Read(key)

			tmpDir, err := ioutil.TempDir("", "_TestCreateAndUnsealWithParams_"+data.desc+"_")
			if err != nil {
				t.Fatalf("Creating temporary directory failed: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			keyFile := tmpDir + "/keydata"

			if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, data.params, key); err != nil {
				t.Fatalf("SealKeyToTPM failed: %v", err)
			}
			defer deleteKey(t, tpm, keyFile)

			resetTPMSimulator(t, tpm, tcti)
			replayLogToTPM(t, tpm, tcti, data.trustedLogPath)
			replayBootParamsToTPM(t, tpm, data.cmdline)

			k, err := LoadSealedKeyObject(keyFile)
			if err != nil {
				t.Fatalf("LoadSealedKeyObject failed: %v", err)
			}

			keyUnsealed, err := k.UnsealFromTPM(tpm, "", false)
			if data.err == "" {
				if err != nil {
					t.Fatalf("UnsealFromTPM failed: %v", err)
				}

				if !bytes.Equal(key, keyUnsealed) {
					t.Errorf("TPM returned the wrong key")
				}
			} else {
				if err == nil {
					t.Fatalf("UnsealFromTPM should have failed")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error string: %s", err)
				}
				if data.errType != nil && data.errType != reflect.ValueOf(err).Type() {
					t.Errorf("Unexpected error type")
				}
			}
		})
	}
}
