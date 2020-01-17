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

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
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

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, f, "", false)
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

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
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

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
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

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, f, testPIN, false)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestUnsealWithPin(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
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

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, f, testPIN, false)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}
}

func TestUnsealRevoked(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUnsealRevoked_")
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

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Cannot open file: %v", err)
	}
	defer f.Close()

	var keydata bytes.Buffer
	if _, err := io.Copy(&keydata, f); err != nil {
		t.Fatalf("Cannot copy key data file: %v", err)
	}

	if err := UpdateKeyAuthPolicy(tpm, keyFile, privFile, nil); err != nil {
		t.Fatalf("UpdateKeyAuthPolicy failed: %v", err)
	}

	_, err = UnsealKeyFromTPM(tpm, &keydata, "", false)
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
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

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
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

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	_, err = UnsealKeyFromTPM(tpm, f, "", false)
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
	}
	if err != ErrPinFail {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUnsealPolicyFail(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
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

	if _, err := tpm.PCREvent(7, tpm2.Event("foo"), nil); err != nil {
		t.Errorf("PCREvent failed: %v", err)
	}

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	_, err = UnsealKeyFromTPM(tpm, f, "", false)
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
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

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
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
	if err := tpm.DictionaryAttackParameters(tpm2.HandleLockout, 0, 7200, 86400, nil); err != nil {
		t.Errorf("DictionaryAttackParameters failed: %v", err)
	}
	defer func() {
		if err := tpm.DictionaryAttackParameters(tpm2.HandleLockout, 32, 7200, 86400, nil); err != nil {
			t.Errorf("DictionaryAttackParameters failed: %v", err)
		}
		if err := tpm.DictionaryAttackLockReset(tpm2.HandleLockout, nil); err != nil {
			t.Errorf("DictionaryAttackLockReset failed: %v", err)
		}
	}()

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	_, err = UnsealKeyFromTPM(tpm, f, "", false)
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
	}
	if err != ErrLockout {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestSealWithProvisioningError(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestSealWithProvisioningError_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	prepare := func(t *testing.T) {
		if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
			t.Fatalf("Failed to provision TPM for test: %v", err)
		}
	}

	run := func(t *testing.T) {
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
		srkContext, _ := tpm.WrapHandle(srkHandle)
		if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		run(t)
	})

	t.Run("InvalidSRK", func(t *testing.T) {
		prepare(t)
		srkContext, _ := tpm.WrapHandle(srkHandle)
		priv, pub, _, _, _, err := tpm.Create(srkContext, nil, &srkTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		fakeSrkContext, _, err := tpm.Load(srkContext, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, fakeSrkContext)

		if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm2.HandleOwner, fakeSrkContext, srkHandle, nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}

		run(t)
	})
}

func TestUnsealProvisioningError(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	prepare := func(t *testing.T) {
		if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
			t.Fatalf("Failed to provision TPM for test: %v", err)
		}
	}
	prepare(t)

	key := make([]byte, 64)
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
		pinContext, _ := tpm.WrapHandle(testCreationParams.PinHandle)
		policyRevokeContext, _ := tpm.WrapHandle(testCreationParams.PolicyRevocationHandle)
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, pinContext, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm2.HandleOwner, policyRevokeContext, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	run := func(t *testing.T) {
		f, err := os.Open(keyFile)
		if err != nil {
			t.Fatalf("Failed to open key data file: %v", err)
		}

		_, err = UnsealKeyFromTPM(tpm, f, "", false)
		if err == nil {
			t.Fatalf("UnsealKeyFromTPM should have failed")
		}
		if err != ErrProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	}

	t.Run("NoSRK", func(t *testing.T) {
		prepare(t)
		srkContext, _ := tpm.WrapHandle(srkHandle)
		if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		run(t)
	})

	t.Run("InvalidSRK", func(t *testing.T) {
		prepare(t)
		srkContext, _ := tpm.WrapHandle(srkHandle)
		priv, pub, _, _, _, err := tpm.Create(srkContext, nil, &srkTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		fakeSrkContext, _, err := tpm.Load(srkContext, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, fakeSrkContext)

		if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkContext.Handle(), nil); err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm2.HandleOwner, fakeSrkContext, srkHandle, nil); err != nil {
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

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	eventLog := "testdata/eventlog3.bin"
	eventLogPathForTesting = eventLog
	efivarsPathForTesting = "testdata/efivars1"
	replayLogToTPM(t, tpm, tcti, eventLog)

	key := make([]byte, 64)
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
								Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}
	if err := SealKeyToTPM(tpm, keyFile, "", &testCreationParams, &params, key); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer deleteKey(t, tpm, keyFile)

	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key data file: %v", err)
	}

	keyUnsealed, err := UnsealKeyFromTPM(tpm, f, "", true)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
	}

	if !bytes.Equal(key, keyUnsealed) {
		t.Errorf("TPM returned the wrong key")
	}

	f.Seek(0, io.SeekStart)

	_, err = UnsealKeyFromTPM(tpm, f, "", true)
	if err == nil {
		t.Fatalf("UnsealKeyFromTPM should have failed")
	}
	if _, ok := err.(InvalidKeyFileError); !ok || err.Error() != "invalid key data file: the authorization policy check failed "+
		"during unsealing" {
		t.Errorf("Unexpected error: %v", err)
	}

	resetTPMSimulator(t, tpm, tcti)
	replayLogToTPM(t, tpm, tcti, eventLog)

	f.Seek(0, io.SeekStart)

	keyUnsealed, err = UnsealKeyFromTPM(tpm, f, "", true)
	if err != nil {
		t.Fatalf("UnsealKeyFromTPM failed: %v", err)
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

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	for _, data := range []struct {
		desc            string
		creationLogPath string
		trustedLogPath  string
		efivars         string
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
										Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}},
		},
		{
			// Test sealing and unsealing with a UC20 style layout
			desc:            "UC20",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog4.bin",
			efivars:         "testdata/efivars1",
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
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}}},
		},
		{
			// Test sealing before upgrading to a kernel signed with a new key, and then unsealing with the old kernel
			desc:            "UC20KernelKeyRotationUnsealPreUpgrade",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog5.bin",
			efivars:         "testdata/efivars2",
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
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}}},
		},
		{
			// Test sealing before upgrading to a kernel signed with a new key, and then unsealing post-upgrade with the new kernel
			desc:            "UC20KernelKeyRotationUnsealPostUpgrade",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog6.bin",
			efivars:         "testdata/efivars2",
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
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}}},
		},
		{
			// Test sealing before applying a UEFI signature DB update and then unsealing before the update is applied
			desc:            "DbUpdateUnsealPreUpdate",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog4.bin",
			efivars:         "testdata/efivars1",
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
				SecureBootDbKeystores: []string{"testdata/updates1"}},
		},
		{
			// Test sealing before applying a UEFI signature DB update and then unsealing post-update
			desc:            "DbUpdateUnsealPostUpdate",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog5.bin",
			efivars:         "testdata/efivars1",
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
				SecureBootDbKeystores: []string{"testdata/updates1"}},
		},
		{
			desc:            "PolicyFail",
			creationLogPath: "testdata/eventlog1.bin",
			trustedLogPath:  "testdata/eventlog5.bin",
			efivars:         "testdata/efivars2",
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
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}}},
			err: "invalid key data file: encountered an error whilst executing the authorization policy assertions: cannot execute PCR " +
				"assertions: cannot execute PolicyOR assertion after PolicyPCR assertion against PCR7: TPM returned an error for parameter 1 " +
				"whilst executing command TPM_CC_PolicyOR: TPM_RC_VALUE (value is out of range or is not correct for the context)",
			errType: reflect.TypeOf(InvalidKeyFileError{}),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			resetTPMSimulator(t, tpm, tcti)
			replayLogToTPM(t, tpm, tcti, data.creationLogPath)

			eventLogPathForTesting = data.creationLogPath
			efivarsPathForTesting = data.efivars

			key := make([]byte, 64)
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

			f, err := os.Open(keyFile)
			if err != nil {
				t.Fatalf("Failed to open key data file: %v", err)
			}

			keyUnsealed, err := UnsealKeyFromTPM(tpm, f, "", false)
			if data.err == "" {
				if err != nil {
					t.Fatalf("UnsealKeyFromTPM failed: %v", err)
				}

				if !bytes.Equal(key, keyUnsealed) {
					t.Errorf("TPM returned the wrong key")
				}
			} else {
				if err == nil {
					t.Fatalf("UnsealKeyFromTPM should have failed")
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
