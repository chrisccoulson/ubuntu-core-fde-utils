package fdeutil

import (
	"flag"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
)

var (
	useTpm         = flag.Bool("use-tpm", false, "")
	tpmPathForTest = flag.String("tpm-path", "/dev/tpm0", "")

	useMssim          = flag.Bool("use-mssim", false, "")
	mssimHost         = flag.String("mssim-host", "localhost", "")
	mssimTpmPort      = flag.Uint("mssim-tpm-port", 2321, "")
	mssimPlatformPort = flag.Uint("mssim-platform-port", 2322, "")
)

func flushContext(t *testing.T, tpm tpm2.TPMContext, context tpm2.ResourceContext) {
	if err := tpm.FlushContext(context); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}
}

func openTPMSimulatorForTesting(t *testing.T) (tpm2.TPMContext, *tpm2.TctiMssim) {
	if !*useMssim {
		t.SkipNow()
	}

	if *useTpm && *useMssim {
		t.Fatalf("Cannot specify both -use-tpm and -use-mssim")
	}

	tcti, err := tpm2.OpenTPMMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
	if err != nil {
		t.Fatalf("Failed to open mssim connection: %v", err)
	}

	tpm, _ := tpm2.NewTPMContext(tcti)
	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		tpmError, isTpmError := err.(tpm2.TPMError)
		if !isTpmError || tpmError.Code != tpm2.ErrorInitialize {
			t.Fatalf("Startup failed: %v", err)
		}
	}

	return tpm, tcti
}

func openTPMForTesting(t *testing.T) tpm2.TPMContext {
	if !*useTpm {
		tpm, _ := openTPMSimulatorForTesting(t)
		return tpm
	}

	if *useTpm && *useMssim {
		t.Fatalf("Cannot specify both -use-tpm and -use-mssim")
	}

	tcti, err := tpm2.OpenTPMDevice(*tpmPathForTest)
	if err != nil {
		t.Fatalf("Failed to open the TPM device: %v", err)
	}

	tpm, _ := tpm2.NewTPMContext(tcti)
	return tpm
}

// clearTPM clears the TPM with platform hierarchy authorization - something that we can only do on the simulator
func clearTPMWithPlatformAuth(t *testing.T, tpm tpm2.TPMContext) {
	if err := tpm.ClearControl(tpm2.HandlePlatform, false, nil); err != nil {
		t.Fatalf("ClearControl failed: %v", err)
	}
	if err := tpm.Clear(tpm2.HandlePlatform, nil); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
}

func resetTPMSimulator(t *testing.T, tpm tpm2.TPMContext, tcti *tpm2.TctiMssim) {
	if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if err := tcti.Reset(); err != nil {
		t.Fatalf("Resetting the TPM simulator failed: %v", err)
	}
	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		t.Fatalf("Startup failed: %v", err)
	}
}

func closeTPM(t *testing.T, tpm tpm2.TPMContext) {
	if *useMssim {
		if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
	}
	if err := tpm.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}
