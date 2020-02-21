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
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"testing"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func validateLockNVIndex(t *testing.T, tpm *tpm2.TPMContext) {
	index, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		t.Fatalf("Cannot create context for lock NV index: %v", err)
	}

	// Validate the properties of the index
	pub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}

	if pub.NameAlg != tpm2.HashAlgorithmSHA256 {
		t.Errorf("Lock NV index has the wrong name algorithm")
	}
	if pub.Attrs.Type() != tpm2.NVTypeOrdinary {
		t.Errorf("Lock NV index has the wrong type")
	}
	if pub.Attrs.AttrsOnly() != tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead|tpm2.AttrNVNoDA|tpm2.AttrNVReadStClear|tpm2.AttrNVWritten {
		t.Errorf("Lock NV index has the wrong attributes")
	}
	if pub.Size != uint16(0) {
		t.Errorf("Lock NV index has the wrong size")
	}

	dataIndex, err := tpm.CreateResourceContextFromTPM(lockNVDataHandle)
	if err != nil {
		t.Fatalf("Cannot create context for lock policy data NV index: %v", err)
	}

	dataPub, _, err := tpm.NVReadPublic(dataIndex)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}
	data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
	if err != nil {
		t.Fatalf("NVRead failed: %v", err)
	}

	var version uint8
	var keyName tpm2.Name
	var clock uint64
	if _, err := tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}

	if version != 0 {
		t.Errorf("Unexpected version for lock NV index policy")
	}

	clockBytes := make([]byte, binary.Size(clock))
	binary.BigEndian.PutUint64(clockBytes, clock)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	if !bytes.Equal(trial.GetDigest(), pub.AuthPolicy) {
		t.Errorf("Lock NV index has the wrong authorization policy")
	}
}

func TestEnsureLockNVIndex(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	clearTPMWithPlatformAuth(t, tpm)

	if err := ensureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("ensureLockNVIndex failed: %v", err)
	}

	validateLockNVIndex(t, tpm.TPMContext)

	index, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		t.Fatalf("No lock NV index created")
	}
	origName := index.Name()

	if err := ensureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("ensureLockNVIndex failed: %v", err)
	}

	index, err = tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		t.Fatalf("No lock NV index created")
	}
	if !bytes.Equal(index.Name(), origName) {
		t.Errorf("lock NV index shouldn't have been recreated")
	}
}

func TestReadAndValidateLockNVIndexPublic(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	prepare := func(t *testing.T) (tpm2.ResourceContext, tpm2.ResourceContext) {
		clearTPMWithPlatformAuth(t, tpm)
		if err := ensureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
			t.Errorf("ensureLockNVIndex failed: %v", err)
		}
		index, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
		if err != nil {
			t.Fatalf("No lock NV index created")
		}
		dataIndex, err := tpm.CreateResourceContextFromTPM(lockNVDataHandle)
		if err != nil {
			t.Fatalf("No lock NV data index created")
		}
		return index, dataIndex
	}

	t.Run("Good", func(t *testing.T) {
		index, _ := prepare(t)
		pub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err != nil {
			t.Fatalf("readAndValidateLockNVIndexPublic failed: %v", err)
		}
		if pub.Index != lockNVHandle {
			t.Errorf("Returned public area has wrong handle")
		}
		if pub.Attrs != lockNVIndexAttrs|tpm2.AttrNVWritten {
			t.Errorf("incorrect lock NV index attributes")
		}
	})

	t.Run("ReadLocked", func(t *testing.T) {
		index, _ := prepare(t)
		if err := tpm.NVReadLock(index, index, nil); err != nil {
			t.Fatalf("NVReadLock failed: %v", err)
		}
		pub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err != nil {
			t.Fatalf("readAndValidateLockNVIndexPublic failed: %v", err)
		}
		if pub.Index != lockNVHandle {
			t.Errorf("Returned public area has wrong handle")
		}
		if pub.Attrs != lockNVIndexAttrs|tpm2.AttrNVWritten {
			t.Errorf("incorrect lock NV index attributes")
		}
	})

	t.Run("NoPolicyDataIndex", func(t *testing.T) {
		index, dataIndex := prepare(t)
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, nil); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}
		pub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("readAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("readAndValidateLockNVIndexPublic should have returned no public area")
		}
		var ruErr tpm2.ResourceUnavailableError
		if !xerrors.As(err, &ruErr) {
			t.Errorf("Unexpected error type")
		}
		if err.Error() != "cannot obtain context for policy data NV index: a resource at handle 0x01801101 is not available on the TPM" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectClockValue", func(t *testing.T) {
		index, dataIndex := prepare(t)

		// Test with a policy data index that indicates a time in the future.

		dataPub, _, err := tpm.NVReadPublic(dataIndex)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}
		data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}
		var version uint8
		var keyName tpm2.Name
		var clock uint64
		if _, err := tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}

		data, err = tpm2.MarshalToBytes(version, keyName, time.ClockInfo.Clock+3600000)
		if err != nil {
			t.Errorf("MarshalToBytes failed: %v", err)
		}

		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, nil); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}

		public := tpm2.NVPublic{
			Index:   lockNVDataHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(data))}
		dataIndex, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		if err := tpm.NVWrite(dataIndex, dataIndex, data, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}
		pub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("readAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("readAndValidateLockNVIndexPublic should have returned no public area")
		}
		if err.Error() != "unexpected clock value in policy data" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectPolicy", func(t *testing.T) {
		clearTPMWithPlatformAuth(t, tpm)

		// Test with a bogus lock NV index that allows writes far in to the future, making it possible
		// to recreate it to remove the read lock bit.

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		keyPublic := createPublicAreaForRSASigningKey(&key.PublicKey)
		keyName, err := keyPublic.Name()
		if err != nil {
			t.Errorf("Cannot compute key name: %v", err)
		}

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}
		time.ClockInfo.Clock += 5000
		clockBytes := make(tpm2.Operand, binary.Size(time.ClockInfo.Clock))
		binary.BigEndian.PutUint64(clockBytes, time.ClockInfo.Clock+3600000000)

		trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
		trial.PolicyCommandCode(tpm2.CommandNVWrite)
		trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
		trial.PolicySigned(keyName, nil)

		public := tpm2.NVPublic{
			Index:      lockNVHandle,
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      lockNVIndexAttrs,
			AuthPolicy: trial.GetDigest(),
			Size:       0}
		index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer tpm.FlushContext(policySession)

		h := tpm2.HashAlgorithmSHA256.NewHash()
		h.Write(policySession.NonceTPM())
		binary.Write(h, binary.BigEndian, int32(0))

		sig, err := rsa.SignPSS(rand.Reader, key, tpm2.HashAlgorithmSHA256.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Errorf("SignPSS failed: %v", err)
		}

		keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}
		defer tpm.FlushContext(keyLoaded)

		signature := tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSAPSS,
			Signature: tpm2.SignatureU{
				Data: &tpm2.SignatureRSAPSS{
					Hash: tpm2.HashAlgorithmSHA256,
					Sig:  tpm2.PublicKeyRSA(sig)}}}

		if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVWrite); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}
		if err := tpm.PolicyCounterTimer(policySession, clockBytes, 8, tpm2.OpUnsignedLT); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}
		if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}

		if err := tpm.NVWrite(index, index, nil, 0, policySession); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		data, err := tpm2.MarshalToBytes(uint8(0), keyName, time.ClockInfo.Clock)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		// Create the data index.
		dataPublic := tpm2.NVPublic{
			Index:   lockNVDataHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(data))}
		dataIndex, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &dataPublic, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		if err := tpm.NVWrite(dataIndex, dataIndex, data, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		pub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("readAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("readAndValidateLockNVIndexPublic should have returned no public area")
		}
		if err.Error() != "incorrect policy for NV index" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

type mockResourceContext struct {
	name   tpm2.Name
	handle tpm2.Handle
}

func (c *mockResourceContext) Name() tpm2.Name {
	return c.name
}

func (c *mockResourceContext) Handle() tpm2.Handle {
	return c.handle
}

func TestComputeStaticPolicy(t *testing.T) {
	block, _ := pem.Decode([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvVGKq3nV0WMpEEQBhroTTHjYRZWHjQlSFXkgvUxurXkMlkti
U8LKJqRUI+ekJ5mCQR5JTMnX59HE/jdL1zYzWP6PjKDlpBU5UcY3chWQ9gM2t7+l
VuY/b8fq4We/P6neNBAMOx8Ip8UAuPzCbWSxCqsMq1Mp3iDUcSGM54OEDupATsqj
LTm6elgHz6Ik92Tzy20Z66mYo02M41VenSSndEFA4zORePek2nHOfklRJvokgnX9
ujwuwUAG80EEOrQavBLQFSzmlc9q0N0GeWp23yfl5Cd84RkzNIFgxnLlUH4og5mN
4Ti3YpI57iXvBsOzFIZ+WXYQROEIP3aiJuNOhQIDAQABAoIBAQCMwk7fFdQDPb3v
SRD1ce4dYpAylG3XUAHG02ujM2vq8OCJ8nymGGMi/fVNSNJFWx58eh83x68OvmnA
Na7e0X62AXcLsSlsqRcYFM9utFg2gccyMXymMsUhwDuD4hZRKGR8wx3E61sNGi1i
XRPWMBJuAyWFUG0FqdUqVC6mh6MtTnh2rzPbU6UnT3a6UsGwy6U1FftuexkXY+bb
mfpwA3lR3p1hgqdKF9DC7C4vsSFzBI2M0vVWX0T76GxhVtVle2XLsKrVjqPnUn1D
59vQt1xr/lluHJp/FP9be0wL3bwOTnDdgpBN2APrFcfyJ6kqJuwL6EdFPSsg3C0M
Q73j0kVBAoGBAOP2FMuhsZxhyNDpTZqS6zbdXy2Z3Mjop70tFj2m11gYOYJ10I/J
7fLPhOuFeNA7Kp8S5iH0hTgk+dd9UD8SV/clj14+tdXjLoMDbqWQ4JXurdk/dXML
46eOuRUUxCFFxmR1EwPzaV1nsNOStFd2HG4s4vpPcOVJ7r0RimOjzj9VAoGBANSa
swXqzleRKrGtDRrqUDZXKP43dyVXgQdLRpAIK6W8GdIbcuvYXmBZG1sFYpK7COJR
/xG6CaPPbDHg8VbE7E5WW3tYi7RvycLJoyYW6EhjqVIMYNVFR6BrHugKNa7KSdHK
UwAYKgL6KYtYEU9ZDBEX2HT9Wd9SGXiwvhl/D/JxAoGAG6AIqRyxL2hSM67yLpc7
VezByf7pWJeJLE24ckQzuINHBN5OJf6sjU5Ep14HZASnh5t8tASz2Dfy5wBSpzIL
4vF0TFGBK6haTJov4HSMIt9HxhoAm66HKhkLqNhZZEbWYfomEcZ/sEgOj7UpkafI
jjl2UCssXTz2Z4cmpCiHp/kCgYA8IaUQv2CtE7nnlvJl8m/NbsmBXV6tiRpNXdUP
V8BAl/sVmf3fBstqpMk/7T38EjppCJgEA4JGepw3X0/jIr9TSMmHEXwyBIwkM7OZ
SlFYaBezxRx+NaIUlTegmYKldUF7vKXNGQiI3whxCO+caasoCn6GWEHbD/V0VUjv
HSj9gQKBgDMhQh5RaTBuU8BIEmzS8DVVv6DUi9Wr8vblVPDEDgTEEeRq1B7OIpnk
QZUMW/hqX6qMtjD1lnygOGT3mL9YlSuGyGymsTqWyJM09XbbK9fXm0g3UGv5sOyb
duwzA18V2dm66mFx1NcqfNyRUbclhN26KAaRnTDQrAaxFIgoO+Xm
-----END RSA PRIVATE KEY-----`))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey failed: %v", err)
	}

	var pinIndexAuthPolicies tpm2.DigestList
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString("199c42684aafe3d9c2e18dcc162a6d3875a40ca2ab8f06228b207135281d995f"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString("78b1915a25b400ec9a87a2830b07aaacfc440f754e0d2027d09799f894d134c0"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString("aa83a598d93a56c9ca6fea7c3ffc4e106357ff6d93e11a9b4ac2b6aae12ba0de"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString("47ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString("203e4bd5d0448c9615cc13fa18e8d39222441cc40204d99a77262068dbd55a43"))

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyOR(pinIndexAuthPolicies)

	pinIndexPub := &tpm2.NVPublic{
		Index:      testCreationParams.PinHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVWritten),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	lockIndexPub := tpm2.NVPublic{
		Index:      lockNVHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear | tpm2.AttrNVWritten),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       0}
	lockName, _ := lockIndexPub.Name()

	for _, data := range []struct {
		desc   string
		alg    tpm2.HashAlgorithmId
		policy tpm2.Digest
	}{
		{
			desc:   "SHA256",
			alg:    tpm2.HashAlgorithmSHA256,
			policy: decodeHexString("6996f631d4ff9ebe51aaf91f155446ea3b845f9d7f3c33d70efc3b44cbf9fde4"),
		},
		{
			desc:   "SHA1",
			alg:    tpm2.HashAlgorithmSHA1,
			policy: decodeHexString("97859d33468dd99d02449128b5c0cda40fc2c272"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, policy, err := computeStaticPolicy(data.alg, &staticPolicyComputeParams{
				key:                  &key.PublicKey,
				pinIndexPub:          pinIndexPub,
				pinIndexAuthPolicies: pinIndexAuthPolicies,
				lockIndexName:        lockName})
			if err != nil {
				t.Fatalf("computeStaticPolicy failed: %v", err)
			}
			if dataout.Algorithm != data.alg {
				t.Errorf("Unexpected session algorithm: %v", err)
			}
			if dataout.AuthorizeKeyPublic.Params.RSADetail().Exponent != uint32(key.PublicKey.E) {
				t.Errorf("Auth key public area has wrong exponent")
			}
			if dataout.AuthorizeKeyPublic.Params.RSADetail().KeyBits != uint16(key.PublicKey.N.BitLen()) {
				t.Errorf("Auth key public area has wrong bit length")
			}
			if !bytes.Equal(dataout.AuthorizeKeyPublic.Unique.RSA(), key.PublicKey.N.Bytes()) {
				t.Errorf("Auth key public area has wrong modulus")
			}
			if dataout.PinIndexHandle != pinIndexPub.Index {
				t.Errorf("Wrong PIN NV index handle")
			}
			if len(dataout.PinIndexAuthPolicies) != len(pinIndexAuthPolicies) {
				t.Fatalf("Wrong number of PIN NV index auth policies")
			}
			for i, d := range dataout.PinIndexAuthPolicies {
				if !bytes.Equal(d, pinIndexAuthPolicies[i]) {
					t.Errorf("Wrong PIN NV index auth policy")
				}
			}
			if !bytes.Equal(policy, data.policy) {
				t.Errorf("Wrong policy digest: %x", policy)
			}
		})
	}
}

func TestComputeDynamicPolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pinIndexPub := &tpm2.NVPublic{
		Index:      testCreationParams.PinHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVWritten),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       8}
	pinName, _ := pinIndexPub.Name()

	digestMatrix := make(map[tpm2.HashAlgorithmId]tpm2.DigestList)

	for _, data := range []string{"foo", "bar", "1234", "ABC"} {
		for _, alg := range []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA512} {
			hasher := alg.NewHash()
			hasher.Write([]byte(data))
			digestMatrix[alg] = append(digestMatrix[alg], hasher.Sum(nil))
		}
	}

	for _, data := range []struct {
		desc   string
		alg    tpm2.HashAlgorithmId
		input  dynamicPolicyComputeParams
		policy tpm2.Digest
	}{
		{
			desc: "Single",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				signAlg:                    tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyCountIndexName:       pinName,
				policyCount:                10,
			},
			policy: decodeHexString("7765bc7816d05f0213eadfea94f4da5c5b7a722aa3169a18a8013608d8690b17"),
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.HashAlgorithmSHA1,
			input: dynamicPolicyComputeParams{
				key:                        key,
				signAlg:                    tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][2]},
				policyCountIndexName:       pinName,
				policyCount:                4551,
			},
			policy: decodeHexString("df99b7aa2bff9e76897446cc12c7e97c4aeb56ac"),
		},
		{
			desc: "SHA256SessionWithSHA512PCRs",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				signAlg:                    tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA512,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA512,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA512][1]},
				policyCountIndexName:       pinName,
				policyCount:                403,
			},
			policy: decodeHexString("c657ca25255cfb45c39477171730e3611b06fcfa35897bb6332437e37d9e5c5d"),
		},
		{
			desc: "MultiplePCRValues",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                    key,
				signAlg:                tpm2.HashAlgorithmSHA256,
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][3],
					digestMatrix[tpm2.HashAlgorithmSHA256][2]},
				policyCountIndexName: pinName,
				policyCount:          5,
			},
			policy: decodeHexString("1ad55f20262a7bbace838334f4ef2a8da113941ae662bcc05df6c73344d8247e"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, err := computeDynamicPolicy(data.alg, &data.input)
			if err != nil {
				t.Fatalf("computeDynamicPolicy failed; %v", err)
			}
			if dataout.SecureBootPCRAlg != data.input.secureBootPCRAlg {
				t.Errorf("Unexpected secure boot PCR algorithm %v", dataout.SecureBootPCRAlg)
			}
			if dataout.UbuntuBootParamsPCRAlg != data.input.ubuntuBootParamsPCRAlg {
				t.Errorf("Unexpected ubuntu boot params PCR algorithm %v", dataout.UbuntuBootParamsPCRAlg)
			}
			if len(dataout.SecureBootORDigests) != len(data.input.secureBootPCRDigests) {
				t.Errorf("Unexpected number of secure boot OR digests")
			}
			if len(dataout.UbuntuBootParamsORDigests) != len(data.input.ubuntuBootParamsPCRDigests) {
				t.Errorf("Unexpected number of ubuntu boot params OR digests")
			}
			if dataout.PolicyCount != data.input.policyCount {
				t.Errorf("Unexpected policy revocation count")
			}

			digestSize := data.alg.Size()
			for _, l := range []tpm2.DigestList{dataout.SecureBootORDigests, dataout.UbuntuBootParamsORDigests} {
				for _, digest := range l {
					if len(digest) != int(digestSize) {
						t.Errorf("Unexpected digest size")
					}
				}
			}

			if !bytes.Equal(data.policy, dataout.AuthorizedPolicy) {
				t.Errorf("Unexpected policy digest returned (got %x, expected %x)", dataout.AuthorizedPolicy, data.policy)
			}

			if dataout.AuthorizedPolicySignature.SigAlg != tpm2.SigSchemeAlgRSAPSS {
				t.Errorf("Unexpected authorized policy signature algorithm")
			}
			if dataout.AuthorizedPolicySignature.Signature.RSAPSS().Hash != data.input.signAlg {
				t.Errorf("Unexpected authorized policy signature digest algorithm")
			}

			h := data.input.signAlg.NewHash()
			h.Write(dataout.AuthorizedPolicy)

			if err := rsa.VerifyPSS(&key.PublicKey, data.input.signAlg.GetHash(), h.Sum(nil),
				[]byte(dataout.AuthorizedPolicySignature.Signature.RSAPSS().Sig),
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("Invalid authorized policy signature: %v", err)
			}
		})
	}
}

func TestLockAccessToSealedKeysUntilTPMReset(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ensureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("ensureLockNVIndex failed: %v", err)
	}

	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pinIndexPub, pinIndexAuthPolicies, err := createPinNvIndex(tpm.TPMContext, testCreationParams.PinHandle, &key.PublicKey, tpm.HmacSession())
	if err != nil {
		t.Fatalf("createPinNvIndex failed: %v", err)
	}
	pinIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer func() {
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), pinIndex, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	staticPolicyData, policy, err := computeStaticPolicy(tpm2.HashAlgorithmSHA256, &staticPolicyComputeParams{
		key:                  &key.PublicKey,
		pinIndexPub:          pinIndexPub,
		pinIndexAuthPolicies: pinIndexAuthPolicies,
		lockIndexName:        lockIndex.Name()})
	if err != nil {
		t.Fatalf("computeStaticPolicy failed: %v", err)
	}

	event := []byte("foo")
	h := crypto.SHA256.New()
	h.Write(event)
	eventDigest := h.Sum(nil)

	h = crypto.SHA256.New()
	h.Write(make([]byte, crypto.SHA256.Size()))
	h.Write(eventDigest)
	pcrDigest := h.Sum(nil)

	policyCount, err := readDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, tpm.HmacSession())
	if err != nil {
		t.Fatalf("readDynamicPolicyCounter failed: %v", err)
	}

	dynamicPolicyParams := dynamicPolicyComputeParams{
		key:                        key,
		signAlg:                    tpm2.HashAlgorithmSHA256,
		secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
		ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
		secureBootPCRDigests:       tpm2.DigestList{pcrDigest},
		ubuntuBootParamsPCRDigests: tpm2.DigestList{pcrDigest},
		policyCountIndexName:       pinIndex.Name(),
		policyCount:                policyCount}

	dynamicPolicyData, err := computeDynamicPolicy(tpm2.HashAlgorithmSHA256, &dynamicPolicyParams)
	if err != nil {
		t.Fatalf("computeDynamicPolicy failed: %v", err)
	}

	for i := 0; i < 2; i++ {
		func() {
			resetTPMSimulator(t, tpm, tcti)

			for _, p := range []int{secureBootPCR, ubuntuBootParamsPCR} {
				if _, err := tpm.PCREvent(tpm.PCRHandleContext(p), event, nil); err != nil {
					t.Fatalf("PCREvent failed: %v", err)
				}
			}

			policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, policySession)

			err = executePolicySession(tpm.TPMContext, policySession, staticPolicyData, dynamicPolicyData, "", tpm.HmacSession())
			if err != nil {
				t.Errorf("executePolicySession failed: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(policySession)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}

			if err := lockAccessToSealedKeysUntilTPMReset(tpm.TPMContext, tpm.HmacSession()); err != nil {
				t.Errorf("lockAccessUntilTPMReset failed: %v", err)
			}

			if err := tpm.PolicyRestart(policySession); err != nil {
				t.Errorf("PolicyRestart failed: %v", err)
			}

			err = executePolicySession(tpm.TPMContext, policySession, staticPolicyData, dynamicPolicyData, "", tpm.HmacSession())
			if err == nil {
				t.Fatalf("executePolicySession should have failed")
			}
			if err.Error() != "policy lock check failed: TPM returned an error whilst executing command TPM_CC_PolicyNV: TPM_RC_NV_LOCKED (NV access locked)" {
				t.Errorf("executePolicySession failed with an unexpected error: %v", err)
			}

			digest, err = tpm.PolicyGetDigest(policySession)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}
		}()
	}
}

func TestExecutePolicy(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := ensureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("ensureLockNVIndex failed: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pinIndexPub, pinIndexAuthPolicies, err := createPinNvIndex(tpm.TPMContext, testCreationParams.PinHandle, &key.PublicKey, tpm.HmacSession())
	if err != nil {
		t.Fatalf("createPinNvIndex failed: %v", err)
	}
	pinIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer func() {
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), pinIndex, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
	}()

	policyCount, err := readDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, tpm.HmacSession())
	if err != nil {
		t.Fatalf("readDynamicPolicyCounter failed: %v", err)
	}

	digestMatrix := make(map[tpm2.HashAlgorithmId]tpm2.DigestList)
	for _, data := range []string{"foo", "bar", "xyz", "1234", "5678"} {
		for _, alg := range []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1} {
			hasher := alg.NewHash()
			hasher.Write([]byte(data))
			dataDigest := hasher.Sum(nil)

			digestSize := alg.Size()

			hasher = alg.NewHash()
			hasher.Write(make([]byte, digestSize))
			hasher.Write(dataDigest)

			digestMatrix[alg] = append(digestMatrix[alg], hasher.Sum(nil))
		}
	}

	type pcrEvent struct {
		index int
		data  string
	}

	for _, data := range []struct {
		desc        string
		alg         tpm2.HashAlgorithmId
		input       dynamicPolicyComputeParams
		pcrEvents   []pcrEvent
		pinDefine   string
		pinInput    string
		policyMatch bool
	}{
		{
			desc: "Single",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyCountIndexName:       pinIndex.Name(),
				policyCount:                policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "SHA1SessionWithSHA256PCRs",
			alg:  tpm2.HashAlgorithmSHA1,
			input: dynamicPolicyComputeParams{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyCountIndexName:       pinIndex.Name(),
				policyCount:                policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "SHA1Session",
			alg:  tpm2.HashAlgorithmSHA1,
			input: dynamicPolicyComputeParams{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA1,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA1,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA1][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA1][1]},
				policyCountIndexName:       pinIndex.Name(),
				policyCount:                policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "WithPIN",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyCountIndexName:       pinIndex.Name(),
				policyCount:                policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			pinDefine:   "1234",
			pinInput:    "1234",
			policyMatch: true,
		},
		{
			desc: "WithIncorrectPIN",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyCountIndexName:       pinIndex.Name(),
				policyCount:                policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			pinDefine:   "1234",
			pinInput:    "12345",
			policyMatch: true,
		},
		{
			desc: "NoMatch",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                    key,
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyCountIndexName: pinIndex.Name(),
				policyCount:          policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "abc",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: false,
		},
		{
			desc: "MultiplePCRValues1",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                    key,
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyCountIndexName: pinIndex.Name(),
				policyCount:          policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
		{
			desc: "MultiplePCRValues2",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                    key,
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyCountIndexName: pinIndex.Name(),
				policyCount:          policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "1234",
				},
			},
			policyMatch: true,
		},
		{
			desc: "MultiplePCRValuesNoMatch",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                    key,
				secureBootPCRAlg:       tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg: tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][0],
					digestMatrix[tpm2.HashAlgorithmSHA256][4]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{
					digestMatrix[tpm2.HashAlgorithmSHA256][1],
					digestMatrix[tpm2.HashAlgorithmSHA256][3]},
				policyCountIndexName: pinIndex.Name(),
				policyCount:          policyCount,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "bar",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "1234",
				},
			},
			policyMatch: false,
		},
		{
			desc: "RevokedPolicy",
			alg:  tpm2.HashAlgorithmSHA256,
			input: dynamicPolicyComputeParams{
				key:                        key,
				secureBootPCRAlg:           tpm2.HashAlgorithmSHA256,
				ubuntuBootParamsPCRAlg:     tpm2.HashAlgorithmSHA256,
				secureBootPCRDigests:       tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][0]},
				ubuntuBootParamsPCRDigests: tpm2.DigestList{digestMatrix[tpm2.HashAlgorithmSHA256][1]},
				policyCountIndexName:       pinIndex.Name(),
				policyCount:                policyCount - 1,
			},
			pcrEvents: []pcrEvent{
				{
					index: secureBootPCR,
					data:  "foo",
				},
				{
					index: ubuntuBootParamsPCR,
					data:  "bar",
				},
			},
			policyMatch: true,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			resetTPMSimulator(t, tpm, tcti)

			lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
			if err != nil {
				t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
			}

			staticPolicyData, policy, err := computeStaticPolicy(data.alg, &staticPolicyComputeParams{
				key:                  &key.PublicKey,
				pinIndexPub:          pinIndexPub,
				pinIndexAuthPolicies: pinIndexAuthPolicies,
				lockIndexName:        lockIndex.Name()})
			if err != nil {
				t.Fatalf("computeStaticPolicy failed: %v", err)
			}
			data.input.signAlg = staticPolicyData.AuthorizeKeyPublic.NameAlg
			dynamicPolicyData, err := computeDynamicPolicy(data.alg, &data.input)
			if err != nil {
				t.Fatalf("computeDynamicPolicy failed: %v", err)
			}

			for _, event := range data.pcrEvents {
				if _, err := tpm.PCREvent(tpm.PCRHandleContext(event.index), []byte(event.data), nil); err != nil {
					t.Fatalf("PCREvent failed: %v", err)
				}
			}

			if data.pinDefine != "" {
				if err := performPINChange(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, "", data.pinDefine, tpm.HmacSession()); err != nil {
					t.Fatalf("performPINChange failed: %v", err)
				}
				defer func() {
					if err := performPINChange(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, data.pinDefine, "", tpm.HmacSession()); err != nil {
						t.Errorf("Resetting PIN failed: %v", err)
					}
				}()
			}

			session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, session)

			err = executePolicySession(tpm.TPMContext, session, staticPolicyData, dynamicPolicyData, data.pinInput, tpm.HmacSession())
			if data.input.policyCount < policyCount {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMError
				if !xerrors.As(err, &e) || e.Code != tpm2.ErrorPolicy || e.Command != tpm2.CommandPolicyNV {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if !data.policyMatch {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMParameterError
				if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorValue || e.Command() != tpm2.CommandPolicyOR || e.Index != 1 {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if data.pinInput != data.pinDefine {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				var e *tpm2.TPMSessionError
				if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorAuthFail || e.Command() != tpm2.CommandPolicySecret {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if err != nil {
				t.Errorf("Failed to execute policy session: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(session)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			match := bytes.Equal(digest, policy)
			if data.policyMatch && data.pinInput == data.pinDefine &&
				data.input.policyCount >= policyCount {
				if !match {
					t.Errorf("Session digest didn't match policy digest")
				}
			} else if match {
				t.Errorf("Session digest shouldn't match policy digest")
			}
		})
	}
}
