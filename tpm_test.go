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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"testing"
	"time"

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

	ekCert *ekCertData
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

	openDefaultTcti = func() (io.ReadWriteCloser, error) {
		var err error
		tcti, err = tpm2.OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
		if err != nil {
			return nil, err
		}
		return tcti, nil
	}

	certData := new(bytes.Buffer)
	tpm2.MarshalToWriter(certData, ekCert)

	tpm, err := SecureConnectToDefaultTPM(certData, nil)
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

	openDefaultTcti = func() (io.ReadWriteCloser, error) {
		return tpm2.OpenTPMDevice(*tpmPathForTest)
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

	if err := tpm.init(nil); err != nil && wasProvisioned {
		t.Fatalf("Failed to restore TPMConnection after reset: %v", err)
	}
}

func closeTPM(t *testing.T, tpm *TPMConnection) {
	if err := tpm.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func createTestCA() ([]byte, crypto.PrivateKey, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot obtain random serial number: %v", err)
	}

	keyId := make([]byte, 32)
	if _, err := rand.Read(keyId); err != nil {
		return nil, nil, fmt.Errorf("cannot obtain random key ID: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate RSA key: %v", err)
	}

	t := time.Now()

	template := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       serial,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Snake Oil TPM Manufacturer"},
			CommonName:   "Snake Oil TPM Manufacturer EK Root CA"},
		NotBefore:             t.Add(time.Hour * -24),
		NotAfter:              t.Add(time.Hour * 240),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyId}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %v", err)
	}

	return cert, key, nil
}

func certifyTPM(tpm *tpm2.TPMContext, caCert []byte, caKey crypto.PrivateKey) error {
	ekContext, pub, _, _, _, _, err := tpm.CreatePrimary(tpm2.HandleEndorsement, nil, &ekTemplate, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("cannot create EK: %v", err)
	}
	defer tpm.FlushContext(ekContext)

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return fmt.Errorf("cannot obtain random serial number for EK cert: %v", err)
	}

	key := rsa.PublicKey{
		N: new(big.Int).SetBytes(pub.Unique.RSA()),
		E: 65537}

	keyId := make([]byte, 32)
	if _, err := rand.Read(keyId); err != nil {
		return fmt.Errorf("cannot obtain random key ID for EK cert: %v", err)
	}

	t := time.Now()

	template := x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serial,
		NotBefore:             t.Add(time.Hour * -24),
		NotAfter:              t.Add(time.Hour * 240),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGEkCertificate},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyId}

	root, err := x509.ParseCertificate(caCert)
	if err != nil {
		return fmt.Errorf("cannot parse CA certificate: %v", err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, root, &key, caKey)
	if err != nil {
		return fmt.Errorf("cannot create EK certificate: %v", err)
	}

	ekCert = &ekCertData{Cert: cert}
	return nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(func() int {
		if *useMssim {
			caCert, caPriv, err := createTestCA()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create test TPM CA certificate and private key: %v\n", err)
				return 1
			}

			rootCAs = append(rootCAs, caCert)

			tcti, err := tpm2.OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open mssim connection: %v", err)
				return 1
			}

			tpm, _ := tpm2.NewTPMContext(tcti)

			if err := func() error {
				defer tpm.Close()

				if err := tpm.Startup(tpm2.StartupClear); err != nil {
					return err
				}

				return certifyTPM(tpm, caCert, caPriv)
			}(); err != nil {
				fmt.Fprintf(os.Stderr, "Simulator startup failed: %v\n", err)
				return 1
			}
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
