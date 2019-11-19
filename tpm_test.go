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
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
)

var testCreationParams = CreationParams{PolicyRevocationHandle: 0x0181ffff, PinHandle: 0x0181fff0}

var (
	useTpm         = flag.Bool("use-tpm", false, "")
	tpmPathForTest = flag.String("tpm-path", "/dev/tpm0", "")

	useMssim          = flag.Bool("use-mssim", false, "")
	mssimHost         = flag.String("mssim-host", "localhost", "")
	mssimTpmPort      = flag.Uint("mssim-tpm-port", 2321, "")
	mssimPlatformPort = flag.Uint("mssim-platform-port", 2322, "")
)

func deleteKey(t *testing.T, tpm *TPMConnection, path string) {
	if err := DeleteKey(tpm, path, nil); err != nil {
		t.Errorf("DeleteKey failed: %v", err)
	}
}

func flushContext(t *testing.T, tpm *TPMConnection, context tpm2.ResourceContext) {
	if err := tpm.FlushContext(context); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}
}

func openTPMSimulatorForTesting(t *testing.T) (*TPMConnection, *tpm2.TctiMssim) {
	if !*useMssim {
		t.SkipNow()
	}

	if *useTpm && *useMssim {
		t.Fatalf("Cannot specify both -use-tpm and -use-mssim")
	}

	var tcti *tpm2.TctiMssim

	connectToDefaultTPM = func() (*tpm2.TPMContext, error) {
		var err error
		tcti, err = tpm2.OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
		if err != nil {
			t.Fatalf("Failed to open mssim connection: %v", err)
		}

		tpm, _ := tpm2.NewTPMContext(tcti)
		return tpm, nil
	}

	tpm, err := ConnectToDefaultTPM()
	if err != nil {
		t.Fatalf("ConnectToDefaultTPM failed: %v", err)
	}

	return tpm, tcti
}

func openTPMForTesting(t *testing.T) *TPMConnection {
	if !*useTpm {
		tpm, _ := openTPMSimulatorForTesting(t)
		return tpm
	}

	if *useTpm && *useMssim {
		t.Fatalf("Cannot specify both -use-tpm and -use-mssim")
	}

	connectToDefaultTPM = func() (*tpm2.TPMContext, error) {
		tcti, err := tpm2.OpenTPMDevice(*tpmPathForTest)
		if err != nil {
			t.Fatalf("Failed to open the TPM device: %v", err)
		}

		tpm, _ := tpm2.NewTPMContext(tcti)
		return tpm, nil
	}

	tpm, err := ConnectToDefaultTPM()
	if err != nil {
		t.Fatalf("ConnectToDefaultTPM failed: %v", err)
	}

	return tpm
}

// clearTPM clears the TPM with platform hierarchy authorization - something that we can only do on the simulator
func clearTPMWithPlatformAuth(t *testing.T, tpm *TPMConnection) {
	if err := tpm.ClearControl(tpm2.HandlePlatform, false, nil); err != nil {
		t.Fatalf("ClearControl failed: %v", err)
	}
	if err := tpm.Clear(tpm2.HandlePlatform, nil); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
}

func resetTPMSimulator(t *testing.T, tpm *TPMConnection, tcti *tpm2.TctiMssim) {
	wasProvisioned := false
	if _, err := tpm.EkContext(); err == nil {
		if _, err := tpm.HmacSession(); err == nil {
			wasProvisioned = true
		}
	}

	if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if err := tcti.Reset(); err != nil {
		t.Fatalf("Resetting the TPM simulator failed: %v", err)
	}
	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		t.Fatalf("Startup failed: %v", err)
	}

	if err := tpm.acquireEkContextAndVerifyTPM(); err != nil && wasProvisioned {
		t.Fatalf("Failed to restore TPMConnection after reset: %v", err)
	}
}

func closeTPM(t *testing.T, tpm *TPMConnection) {
	if err := tpm.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(func() int {
		err := func() error {
			if !*useMssim {
				return nil
			}

			tcti, err := tpm2.OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
			if err != nil {
				return fmt.Errorf("cannot open mssim connection: %v", err)
			}

			tpm, _ := tpm2.NewTPMContext(tcti)
			defer tpm.Close()

			return tpm.Startup(tpm2.StartupClear)
		}()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Simulator startup failed: %v\n", err)
			return 1
		}

		defer func() {
			if !*useMssim {
				return
			}

			tcti, err := tpm2.OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open mssim connection: %v\n", err)
				return
			}

			tpm, _ := tpm2.NewTPMContext(tcti)
			if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator shutdown failed: %v\n", err)
			}
			if err := tcti.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to stop TPM simulator: %v\n", err)
			}
			tpm.Close()
		}()

		return m.Run()
	}())
}
