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
	"encoding/binary"
	"encoding/hex"
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

var testCreationParams = CreationParams{PinHandle: 0x0181fff0}

var (
	useTpm         = flag.Bool("use-tpm", false, "")
	tpmPathForTest = flag.String("tpm-path", "/dev/tpm0", "")

	useMssim          = flag.Bool("use-mssim", false, "")
	mssimHost         = flag.String("mssim-host", "localhost", "")
	mssimTpmPort      = flag.Uint("mssim-tpm-port", 2321, "")
	mssimPlatformPort = flag.Uint("mssim-platform-port", 2322, "")

	testCACert []byte
	testCAKey  crypto.PrivateKey

	testEkCert []byte

	testEncodedEkCertChain []byte
)

func decodeHexString(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func deleteKey(t *testing.T, tpm *TPMConnection, path string) {
	if err := DeleteKey(tpm, path); err != nil {
		t.Errorf("DeleteKey failed: %v", err)
	}
}

func flushContext(t *testing.T, tpm *TPMConnection, context tpm2.HandleContext) {
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

	tpm, err := SecureConnectToDefaultTPM(bytes.NewReader(testEncodedEkCertChain), nil)
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
	if err := tpm.ClearControl(tpm.PlatformHandleContext(), false, nil); err != nil {
		t.Fatalf("ClearControl failed: %v", err)
	}
	if err := tpm.Clear(tpm.PlatformHandleContext(), nil); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
}

func resetTPMSimulator(t *testing.T, tpm *TPMConnection, tcti *tpm2.TctiMssim) {
	if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if err := tcti.Reset(); err != nil {
		t.Fatalf("Resetting the TPM simulator failed: %v", err)
	}
	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		t.Fatalf("Startup failed: %v", err)
	}

	if err := tpm.init(); err != nil {
		t.Fatalf("Failed to reinitialize TPMConnection after reset: %v", err)
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

func createTestEkCert(tpm *tpm2.TPMContext, caCert []byte, caKey crypto.PrivateKey) ([]byte, error) {
	ekContext, pub, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, &ekTemplate, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create EK: %v", err)
	}
	defer tpm.FlushContext(ekContext)

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, fmt.Errorf("cannot obtain random serial number for EK cert: %v", err)
	}

	key := rsa.PublicKey{
		N: new(big.Int).SetBytes(pub.Unique.RSA()),
		E: 65537}

	keyId := make([]byte, 32)
	if _, err := rand.Read(keyId); err != nil {
		return nil, fmt.Errorf("cannot obtain random key ID for EK cert: %v", err)
	}

	t := time.Now()

	tpmDeviceAttrValues := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidTcgAttributeTpmManufacturer, Value: "id:49424d00"},
			pkix.AttributeTypeAndValue{Type: oidTcgAttributeTpmModel, Value: "FakeTPM"},
			pkix.AttributeTypeAndValue{Type: oidTcgAttributeTpmVersion, Value: "id:00010002"}}}
	tpmDeviceAttrData, err := asn1.Marshal(tpmDeviceAttrValues)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal SAN value: %v", err)
	}
	sanData, err := asn1.Marshal([]asn1.RawValue{
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanDirectoryNameTag, IsCompound: true, Bytes: tpmDeviceAttrData}})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal SAN value: %v", err)
	}
	sanExtension := pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: true,
		Value:    sanData}

	template := x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serial,
		NotBefore:             t.Add(time.Hour * -24),
		NotAfter:              t.Add(time.Hour * 240),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTcgKpEkCertificate},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyId,
		ExtraExtensions:       []pkix.Extension{sanExtension}}

	root, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CA certificate: %v", err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, root, &key, caKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create EK certificate: %v", err)
	}

	return cert, nil
}

func certifyTPM(tpm *tpm2.TPMContext) error {
	if cert, err := createTestEkCert(tpm, testCACert, testCAKey); err != nil {
		return err
	} else {
		caCert, _ := x509.ParseCertificate(testCACert)
		b := new(bytes.Buffer)
		if err := EncodeEkCertificateChain(nil, []*x509.Certificate{caCert}, b); err != nil {
			return fmt.Errorf("cannot encode EK certificate chain: %v", err)
		}
		testEkCert = cert
		testEncodedEkCertChain = b.Bytes()

		nvPub := tpm2.NVPublic{
			Index:   ekCertHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPPWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVPlatformCreate),
			Size:    uint16(len(cert))}
		index, err := tpm.NVDefineSpace(tpm.PlatformHandleContext(), nil, &nvPub, nil)
		if err != nil {
			return fmt.Errorf("cannot define NV index for EK certificate: %v", err)
		}
		if err := tpm.NVWrite(tpm.PlatformHandleContext(), index, tpm2.MaxNVBuffer(cert), 0, nil); err != nil {
			return fmt.Errorf("cannot write EK certificate to NV index: %v", err)
		}
	}
	return nil
}

func TestConnectToDefaultTPM(t *testing.T) {
	openDefaultTcti = func() (io.ReadWriteCloser, error) {
		return tpm2.OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
	}

	connectAndClear := func(t *testing.T) *TPMConnection {
		tpm, _ := openTPMSimulatorForTesting(t)
		clearTPMWithPlatformAuth(t, tpm)
		return tpm
	}

	run := func(t *testing.T, hasEk bool, cleanup func(*TPMConnection)) {
		tpm, err := ConnectToDefaultTPM()
		if err != nil {
			t.Fatalf("ConnectToDefaultTPM failed: %v", err)
		}
		defer func() {
			if cleanup != nil {
				cleanup(tpm)
			}
			closeTPM(t, tpm)
		}()

		if len(tpm.VerifiedEkCertChain()) > 0 {
			t.Errorf("Should be no verified EK cert chain")
		}
		if tpm.VerifiedDeviceAttributes() != nil {
			t.Errorf("Should be no verified device attributes")
		}
		rc, err := tpm.EkContext()
		if !hasEk {
			if err == nil {
				t.Fatalf("TPMConnection.EkContext should have returned an error")
			}
			if rc != nil {
				t.Errorf("TPMConnection.EkContext should have returned a nil context")
			}
			if err != ErrProvisioning {
				t.Errorf("TPMConnection.EkContext returned an unexpected error: %v", err)
			}
		} else {
			if err != nil {
				t.Fatalf("TPMConnection.EkContext failed: %v", err)
			}
			if rc == nil {
				t.Fatalf("TPMConnection.EkContext returned a nil context")
			}
			if rc.Handle() != ekHandle {
				t.Errorf("TPMConnection.EkContext returned an unexpected context")
			}
		}
		session := tpm.HmacSession()
		if session == nil || session.Handle().Type() != tpm2.HandleTypeHMACSession {
			t.Fatalf("TPMConnection.HmacSession returned invalid session context")
		}
	}

	t.Run("Unprovisioned", func(t *testing.T) {
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		run(t, false, nil)
	})

	t.Run("Provisioned", func(t *testing.T) {
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
				t.Fatalf("ProvisionTPM failed: %v", err)
			}
		}()

		run(t, true, nil)
	})

	t.Run("InvalidEK", func(t *testing.T) {
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			primary, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, &ekTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer flushContext(t, tpm, primary)

			sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)
			sessionContext.SetAttrs(tpm2.AttrContinueSession)

			if _, _, err := tpm.PolicySecret(tpm.EndorsementHandleContext(), sessionContext, nil, nil, 0, nil); err != nil {
				t.Fatalf("PolicySecret failed: %v", err)
			}

			priv, pub, _, _, _, err := tpm.Create(primary, nil, &ekTemplate, nil, nil, sessionContext)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			if _, _, err := tpm.PolicySecret(tpm.EndorsementHandleContext(), sessionContext, nil, nil, 0, nil); err != nil {
				t.Fatalf("PolicySecret failed: %v", err)
			}

			context, err := tpm.Load(primary, priv, pub, sessionContext)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			defer flushContext(t, tpm, context)

			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), context, ekHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}
		}()

		run(t, false, nil)
	})

	t.Run("UnprovisionedWithEndorsementAuth", func(t *testing.T) {
		testAuth := []byte("foo")
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		run(t, false, func(tpm *TPMConnection) {
			clearTPMWithPlatformAuth(t, tpm)
		})
	})
}

func TestSecureConnectToDefaultTPM(t *testing.T) {
	openDefaultTcti = func() (io.ReadWriteCloser, error) {
		return tpm2.OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
	}

	connectAndClear := func(t *testing.T) *TPMConnection {
		tpm, _ := openTPMSimulatorForTesting(t)
		clearTPMWithPlatformAuth(t, tpm)
		return tpm
	}

	run := func(t *testing.T, ekCert io.Reader, hasEk bool, auth []byte, cleanup func(*TPMConnection)) {
		tpm, err := SecureConnectToDefaultTPM(ekCert, auth)
		if err != nil {
			t.Fatalf("SecureConnectToDefaultTPM failed: %v", err)
		}
		defer func() {
			if cleanup != nil {
				cleanup(tpm)
			}
			closeTPM(t, tpm)
		}()

		if len(tpm.VerifiedEkCertChain()) != 2 {
			t.Fatalf("Unexpected number of certificates in chain")
		}
		if !bytes.Equal(tpm.VerifiedEkCertChain()[0].Raw, testEkCert) {
			t.Errorf("Unexpected leaf certificate")
		}

		if tpm.VerifiedDeviceAttributes() == nil {
			t.Fatalf("Should have verified device attributes")
		}
		if tpm.VerifiedDeviceAttributes().Manufacturer != tpm2.TPMManufacturerIBM {
			t.Errorf("Unexpected verified manufacturer")
		}
		if tpm.VerifiedDeviceAttributes().Model != "FakeTPM" {
			t.Errorf("Unexpected verified model")
		}
		if tpm.VerifiedDeviceAttributes().FirmwareVersion != binary.BigEndian.Uint32([]byte{0x00, 0x01, 0x00, 0x02}) {
			t.Errorf("Unexpected verified firmware version")
		}

		rc, err := tpm.EkContext()
		if !hasEk {
			if err == nil {
				t.Fatalf("TPMConnection.EkContext should have returned an error")
			}
			if rc != nil {
				t.Errorf("TPMConnection.EkContext should have returned a nil context")
			}
			if err != ErrProvisioning {
				t.Errorf("TPMConnection.EkContext returned an unexpected error: %v", err)
			}
		} else {
			if err != nil {
				t.Fatalf("TPMConnection.EkContext failed: %v", err)
			}
			if rc == nil {
				t.Fatalf("TPMConnection.EkContext returned a nil context")
			}
			if rc.Handle() != ekHandle {
				t.Errorf("TPMConnection.EkContext returned an unexpected context")
			}
		}
		session := tpm.HmacSession()
		if session == nil || session.Handle().Type() != tpm2.HandleTypeHMACSession {
			t.Fatalf("TPMConnection.HmacSession returned invalid session context")
		}
	}

	t.Run("Unprovisioned", func(t *testing.T) {
		// Test that we verify successfully with a transient EK
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		run(t, bytes.NewReader(testEncodedEkCertChain), false, nil, nil)
	})

	t.Run("UnprovisionedWithEndorsementAuth", func(t *testing.T) {
		// Test that we verify successfully with a transient EK when the endorsement hierarchy has an authorization value and we know it
		testAuth := []byte("56789")
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testEncodedEkCertChain), false, testAuth, func(tpm *TPMConnection) {
			clearTPMWithPlatformAuth(t, tpm)
		})
	})

	t.Run("UnprovisionedWithUnknownEndorsementAuth", func(t *testing.T) {
		// Test that we get the correct error if there is no persistent EK and we can't create a transient one
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), []byte("1234"), nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		defer func() {
			tpm, err := ConnectToDefaultTPM()
			if err != nil {
				t.Fatalf("ConnectToTPM failed: %v", err)
			}
			defer closeTPM(t, tpm)
			clearTPMWithPlatformAuth(t, tpm)
		}()

		_, err := SecureConnectToDefaultTPM(bytes.NewReader(testEncodedEkCertChain), nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if err != ErrProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Provisioned", func(t *testing.T) {
		// Test that we verify successfully with the properly provisioned persistent EK
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
				t.Fatalf("ProvisionTPM failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testEncodedEkCertChain), true, nil, nil)
	})

	t.Run("CallerProvidedEkCert", func(t *testing.T) {
		// Test that we can verify without a TPM provisioned EK certificate
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		cert, _ := x509.ParseCertificate(testEkCert)
		caCert, _ := x509.ParseCertificate(testCACert)

		certData := new(bytes.Buffer)
		if err := EncodeEkCertificateChain(cert, []*x509.Certificate{caCert}, certData); err != nil {
			t.Fatalf("EncodeEkCertificateChain failed: %v", err)
		}

		run(t, certData, false, nil, nil)
	})

	t.Run("InvalidEkCert", func(t *testing.T) {
		// Test that we get the right error if the provided EK cert data is invalid
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		certData := new(bytes.Buffer)
		certData.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		_, err := SecureConnectToDefaultTPM(certData, nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(EkCertVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("EkCertUnknownIssuer", func(t *testing.T) {
		// Test that we get the right error if the provided EK cert has an unknown issuer
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		certData := func() io.Reader {
			caCertRaw, caKey, err := createTestCA()
			if err != nil {
				t.Fatalf("createTestCA failed: %v", err)
			}

			tpm, err := ConnectToDefaultTPM()
			if err != nil {
				t.Fatalf("ConnectToDefaultTPM failed: %v", err)
			}
			defer closeTPM(t, tpm)

			certRaw, err := createTestEkCert(tpm.TPMContext, caCertRaw, caKey)
			if err != nil {
				t.Fatalf("createTestEkCert failed: %v", err)
			}

			cert, _ := x509.ParseCertificate(certRaw)
			caCert, _ := x509.ParseCertificate(caCertRaw)

			b := new(bytes.Buffer)
			if err := EncodeEkCertificateChain(cert, []*x509.Certificate{caCert}, b); err != nil {
				t.Fatalf("EncodeEkCertificateChain failed: %v", err)
			}
			return b
		}()

		_, err := SecureConnectToDefaultTPM(certData, nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(EkCertVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectPersistentEK", func(t *testing.T) {
		// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			// This produces a primary key that doesn't match the certificate created in TestMain
			sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
			ekContext, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, &ekTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer tpm.FlushContext(ekContext)
			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ekContext, ekHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testEncodedEkCertChain), false, nil, nil)
	})

	t.Run("IncorrectPersistentEKWithEndorsementAuth", func(t *testing.T) {
		// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate and we have set the
		// endorsement hierarchy authorization value
		testAuth := []byte("12345")
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			// This produces a primary key that doesn't match the certificate created in TestMain
			sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
			ekContext, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, &ekTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer tpm.FlushContext(ekContext)
			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ekContext, ekHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testEncodedEkCertChain), false, testAuth, func(tpm *TPMConnection) {
			clearTPMWithPlatformAuth(t, tpm)
		})
	})

	t.Run("IncorrectPersistentEKWithUnknownEndorsementAuth", func(t *testing.T) {
		// Verify that we get the expected error if the persistent EK doesn't match the certificate and we can't create a transient EK
		testAuth := []byte("12345")
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			// This produces a primary key that doesn't match the certificate created in TestMain
			sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
			ekContext, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, &ekTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer tpm.FlushContext(ekContext)
			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ekContext, ekHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		defer func() {
			tpm, err := ConnectToDefaultTPM()
			if err != nil {
				t.Fatalf("ConnectToTPM failed: %v", err)
			}
			defer closeTPM(t, tpm)
			clearTPMWithPlatformAuth(t, tpm)
		}()

		_, err := SecureConnectToDefaultTPM(bytes.NewReader(testEncodedEkCertChain), nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(TPMVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(func() int {
		if *useMssim {
			if cert, key, err := createTestCA(); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create test TPM CA certificate and private key: %v\n", err)
				return 1
			} else {
				h := crypto.SHA256.New()
				h.Write(cert)
				rootCAHashes = append(rootCAHashes, h.Sum(nil))

				testCACert = cert
				testCAKey = key
			}

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

				return certifyTPM(tpm)
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
