package fdeutil

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

func TestDecodeSecureBootDb(t *testing.T) {
	var (
		microsoftRootCANameDER = []byte{0x30, 0x81, 0x88, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
			0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
			0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e,
			0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31,
			0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x4d, 0x69, 0x63, 0x72, 0x6f,
			0x73, 0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f,
			0x6e, 0x31, 0x32, 0x30, 0x30, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x29, 0x4d, 0x69, 0x63,
			0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x65, 0x72,
			0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
			0x69, 0x74, 0x79, 0x20, 0x32, 0x30, 0x31, 0x30}
		microsoftThirdPartyRootCANameDER = []byte{0x30, 0x81, 0x91, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
			0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
			0x08, 0x13, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10,
			0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e,
			0x64, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x4d, 0x69, 0x63,
			0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74,
			0x69, 0x6f, 0x6e, 0x31, 0x3b, 0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x32, 0x4d,
			0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72,
			0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x54, 0x68, 0x69, 0x72, 0x64, 0x20, 0x50, 0x61, 0x72,
			0x74, 0x79, 0x20, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x20,
			0x52, 0x6f, 0x6f, 0x74}
		microsoftOwnerGuid = tcglog.EFIGUID{A: 0x77fa9abd, B: 0x0359, C: 0x4d32, D: 0xbd60,
			E: [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}}
		microsoftPCASubject string = "CN=Microsoft Windows Production PCA 2011,O=Microsoft Corporation," +
			"L=Redmond,ST=Washington,C=US"
		microsoftPCASerial        = []byte{0x61, 0x07, 0x76, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}
		microsoftCASubject string = "CN=Microsoft Corporation UEFI CA 2011,O=Microsoft Corporation," +
			"L=Redmond,ST=Washington,C=US"
		microsoftCASerial = []byte{0x61, 0x08, 0xd3, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}

		testRootCANameDER = []byte{0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
			0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x45, 0x46, 0x49, 0x20, 0x43, 0x41}
		testOwnerGuid = tcglog.EFIGUID{A: 0xd1b37b32, B: 0x172d, C: 0x4d2a, D: 0x909f,
			E: [...]uint8{0xc7, 0x80, 0x81, 0x50, 0x17, 0x86}}
		testCASubject string = "CN=Test UEFI CA"
		testCASerial1        = []byte{0x1b, 0xd2, 0xa0, 0xd5, 0x63, 0xe5, 0x90, 0x1d, 0x6d, 0x14, 0x88,
			0x43, 0x1b, 0xc6, 0x39, 0xbf, 0x06, 0xe0, 0xf4, 0xfa}
	)

	type certId struct {
		issuer  []byte
		subject string
		serial  []byte
		owner   tcglog.EFIGUID
	}
	for _, data := range []struct {
		desc       string
		path       string
		certs      []certId
		signatures int
	}{
		{
			desc: "db1",
			path: "testdata/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCANameDER,
					subject: microsoftPCASubject,
					serial:  microsoftPCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  microsoftThirdPartyRootCANameDER,
					subject: microsoftCASubject,
					serial:  microsoftCASerial,
					owner:   microsoftOwnerGuid,
				},
			},
			signatures: 2,
		},
		{
			desc: "db2",
			path: "testdata/efivars1/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCANameDER,
					subject: microsoftPCASubject,
					serial:  microsoftPCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  microsoftThirdPartyRootCANameDER,
					subject: microsoftCASubject,
					serial:  microsoftCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  testRootCANameDER,
					subject: testCASubject,
					serial:  testCASerial1,
					owner:   testOwnerGuid,
				},
			},
			signatures: 3,
		},
		{
			desc: "db3",
			path: "testdata/efivars2/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCANameDER,
					subject: microsoftPCASubject,
					serial:  microsoftPCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  microsoftThirdPartyRootCANameDER,
					subject: microsoftCASubject,
					serial:  microsoftCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  testRootCANameDER,
					subject: testCASubject,
					serial:  testCASerial1,
					owner:   testOwnerGuid,
				},
				{
					issuer:  testRootCANameDER,
					subject: testCASubject,
					serial: []byte{0x2c, 0x7a, 0x9e, 0xf3, 0xe5, 0x0a, 0xb1, 0x67, 0x95, 0x30,
						0x21, 0xd3, 0x2e, 0x4e, 0x92, 0x33, 0xcb, 0xc4, 0x80, 0xa9},
					owner: testOwnerGuid,
				},
			},
			signatures: 4,
		},
		{
			desc: "dbx1",
			path: "testdata/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer: microsoftRootCANameDER,
					subject: "CN=Microsoft Windows PCA 2010,O=Microsoft Corporation," +
						"L=Redmond,ST=Washington,C=US",
					serial: []byte{0x61, 0x0c, 0x6a, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
					owner: tcglog.EFIGUID{A: 0x00000000, B: 0x0000, C: 0x0000, D: 0x0000,
						E: [...]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				},
			},
			signatures: 78,
		},
		{
			desc:       "dbx2",
			path:       "testdata/efivars1/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			signatures: 1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			f, err := os.Open(data.path)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer f.Close()
			d, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}

			signatures, err := decodeSecureBootDb(bytes.NewReader(d[4:]))
			if err != nil {
				t.Fatalf("decodeSecureBootDb failed: %v", err)
			}
			if len(signatures) != data.signatures {
				t.Fatalf("Unexpected number of signatures (got %d, expected %d)", len(signatures),
					data.signatures)
			}
			i := 0
			for _, s := range signatures {
				if s.signatureType != efiCertX509Guid {
					continue
				}

				c, err := x509.ParseCertificate(s.data)
				if err != nil {
					t.Errorf("ParseCertificate failed: %v", err)
				}

				if s.owner != data.certs[i].owner {
					t.Errorf("Unexpected owner (got %s, expected %s)", &s.owner,
						&data.certs[i].owner)
				}
				if !bytes.Equal(c.RawIssuer, data.certs[i].issuer) {
					t.Errorf("Unexpected issuer: %s", c.Issuer)
				}
				if c.Subject.String() != data.certs[i].subject {
					t.Errorf("Unexpected subject: %s", c.Subject.String())
				}
				if !bytes.Equal(c.SerialNumber.Bytes(), data.certs[i].serial) {
					t.Errorf("Unexpected serial number (got %x, expected %x)",
						c.SerialNumber.Bytes(), data.certs[i].serial)
				}
				i++
			}
		})
	}
}

func TestClassifySecureBootEvents(t *testing.T) {
	for _, data := range []struct {
		desc            string
		logPath         string
		classifications []eventClass
		err             string
	}{
		{
			desc:    "SecureBootEnabled",
			logPath: "testdata/eventlog1.bin",
			classifications: []eventClass{
				eventClassUnclassified,
				eventClassUnclassified,
				eventClassKEK,
				eventClassDb,
				eventClassDbx,
				eventClassUnclassified,
				eventClassInitialAppVerification,
				eventClassAppVerification,
				eventClassAppVerification},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			validatedLog, err := tcglog.ReplayAndValidateLog(data.logPath, tcglog.LogOptions{})
			if err != nil {
				t.Fatalf("ReplayAndValidateLog failed: %v", err)
			}

			classifiedEvents, err := classifySecureBootEvents(validatedLog.ValidatedEvents)
			if data.err == "" {
				if err != nil {
					t.Fatalf("classifySecureBootEvents failed: %v", err)
				}
				if len(classifiedEvents) != len(data.classifications) {
					t.Fatalf("Unexpected number of events")
				}
				for i, class := range data.classifications {
					if class != classifiedEvents[i].class {
						t.Errorf("Unexpected classification %d for event at index %d",
							classifiedEvents[i].class, i)
					}
				}
			} else {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestComputeDbUpdate(t *testing.T) {
	for _, data := range []struct {
		desc          string
		orig          string
		update        string
		sha1hash      [20]byte
		newSignatures int
	}{
		{
			desc:   "AppendOneCertToDb",
			orig:   "testdata/efivars1/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update: "testdata/updates1/db/1.bin",
			sha1hash: [...]byte{0x49, 0x78, 0x5b, 0x43, 0x6f, 0xbc, 0xbb, 0xc4, 0x34, 0x9d, 0xfa, 0xe2,
				0xc0, 0x89, 0x54, 0x77, 0xba, 0xba, 0x15, 0xe8},
			newSignatures: 1,
		},
		{
			desc:   "AppendExistingCertToDb",
			orig:   "testdata/efivars2/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update: "testdata/updates1/db/1.bin",
			sha1hash: [...]byte{0x49, 0x78, 0x5b, 0x43, 0x6f, 0xbc, 0xbb, 0xc4, 0x34, 0x9d, 0xfa, 0xe2,
				0xc0, 0x89, 0x54, 0x77, 0xba, 0xba, 0x15, 0xe8},
		},
		{
			desc:   "AppendMsDbxUpdate",
			orig:   "testdata/efivars1/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update: "testdata/updates/dbx/MS-2016-08-08.bin",
			sha1hash: [...]byte{0x96, 0xf7, 0xdc, 0x10, 0x4e, 0xe3, 0x4a, 0x0c, 0xe8, 0x42, 0x5a, 0xac,
				0x20, 0xf2, 0x9e, 0x2b, 0x2a, 0xba, 0x9d, 0x7e},
			newSignatures: 77,
		},
		{
			desc:   "AppendDbxUpdateWithDuplicateSignatures",
			orig:   "testdata/efivars3/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update: "testdata/updates2/dbx/1.bin",
			sha1hash: [...]byte{0xb4, 0x95, 0x64, 0xb2, 0xda, 0xee, 0x39, 0xb0, 0x1b, 0x52, 0x4b, 0xef,
				0x75, 0xcf, 0x9c, 0xde, 0x2c, 0x3a, 0x2a, 0x0d},
			newSignatures: 2,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			orig, err := os.Open(data.orig)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			update, err := os.Open(data.update)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			b, err := computeDbUpdate(io.NewSectionReader(orig, 4, (1<<63)-1), update)
			if err != nil {
				t.Fatalf("computeDbUpdate failed: %v", err)
			}

			if _, err := decodeSecureBootDb(bytes.NewReader(b)); err != nil {
				t.Errorf("decodeSecureBootDb failed: %v", err)
			}

			origb, err := ioutil.ReadAll(orig)
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}
			orig.Seek(0, io.SeekStart)

			if !bytes.Equal(origb[4:], b[:len(origb)-4]) {
				t.Errorf("computeDbUpdate didn't perform an append")
			}

			signatures, err := decodeSecureBootDb(bytes.NewReader(b[len(origb)-4:]))
			if err != nil {
				t.Errorf("decodeSecureBootDb failed: %v", err)
			}

			if len(signatures) != data.newSignatures {
				t.Errorf("Incorrect number of new signatures (got %d, expected %d)",
					len(signatures), data.newSignatures)
			}

			h := sha1.New()
			var attrs uint32
			if err := binary.Read(orig, binary.LittleEndian, &attrs); err != nil {
				t.Fatalf("binary.Read failed: %v", err)
			}
			if err := binary.Write(h, binary.LittleEndian, attrs); err != nil {
				t.Fatalf("binary.Write failed: %v", err)
			}
			h.Write(b)

			if !bytes.Equal(data.sha1hash[:], h.Sum(nil)) {
				t.Errorf("Unexpected updated contents (sha1 got %x, expected %x)", h.Sum(nil),
					data.sha1hash[:])
			}
		})
	}
}

func replayLogToTPM(t *testing.T, tpm *TPMConnection, tcti *tpm2.TctiMssim, logPath string) {
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("Open failed: %v\n", err)
	}
	defer f.Close()

	log, err := tcglog.NewLog(f, tcglog.LogOptions{})
	if err != nil {
		t.Fatalf("NewLog failed: %v", err)
	}

	for {
		event, err := log.NextEvent()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("NextEvent failed: %v", err)
		}

		if event.EventType == tcglog.EventTypeNoAction {
			continue
		}

		var digests tpm2.TaggedHashList
		for alg, digest := range event.Digests {
			digests = append(digests, tpm2.TaggedHash{HashAlg: tpm2.HashAlgorithmId(alg), Digest: tpm2.Digest(digest)})
		}
		if err := tpm.PCRExtend(tpm2.Handle(event.PCRIndex), digests, nil); err != nil {
			t.Fatalf("PCRExtend failed: %v", err)
		}
	}
}

func TestComputeSecureBootPolicyDigests(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.SkipNow()
	}

	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc    string
		logPath string
		efivars string
		params  *SealParams
		digests tpm2.DigestList
		err     string
	}{
		{
			// Test with a classic style boot chain with grub and kernel verified against the UEFI db
			desc:    "VerifyFromDbClassic",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}},
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81}},
		},
		{
			// Test with a classic style boot chain with grub and kernel verified against the UEFI db, and grub signed by the
			// actual CA certificate
			desc:    "VerifyDirectCASignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.ca1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}},
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81}},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// and the kernel are verified by the UEFI db
			desc:    "VerifyFromDbUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
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
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81}},
		},
		{
			// Test with a GRUB binary that has an invalid signature
			desc:    "InvalidGrubSignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.2"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}},
			err: "cannot process events from event log: cannot process KEK measurement event: cannot process KEK measurement event 0: " +
				"cannot process subsequent events from event log: cannot process db measurement event: cannot process db measurement event 0: " +
				"cannot process subsequent events from event log: cannot process dbx measurement event: cannot process dbx measurement event " +
				"0: cannot process subsequent events from event log: cannot compute OS load events: cannot compute events for component at " +
				"index 0 (testdata/mockshim1.efi.signed.1): cannot process Shim executable: cannot compute events for subsequent components: " +
				"cannot compute events for component at index 0 (testdata/mock.efi.signed.2): cannot process executable: cannot compute " +
				"measurement for PE binary verification: no root certificate found",
		},
		{
			// Test with an unsigned kernel
			desc:    "NoKernelSignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi")}}}}}}},
			err: "cannot process events from event log: cannot process KEK measurement event: cannot process KEK measurement event 0: " +
				"cannot process subsequent events from event log: cannot process db measurement event: cannot process db measurement event 0: " +
				"cannot process subsequent events from event log: cannot process dbx measurement event: cannot process dbx measurement event " +
				"0: cannot process subsequent events from event log: cannot compute OS load events: cannot compute events for component at " +
				"index 0 (testdata/mockshim1.efi.signed.1): cannot process Shim executable: cannot compute events for subsequent components: " +
				"cannot compute events for component at index 0 (testdata/mock.efi.signed.1): cannot process executable: cannot compute events " +
				"for subsequent components: cannot compute events for component at index 0 (testdata/mock.efi): cannot process executable: " +
				"cannot compute measurement for PE binary verification: cannot read signature length: EOF",
		},
		{
			// Test with secure boot enforcement disabled in shim
			desc:    "ShimVerificationDisabled",
			logPath: "testdata/eventlog2.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}},
			err: "the current boot was performed with validation disabled in Shim",
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// and the kernel are verified by shim's vendor cert
			desc:    "VerifyGrubAndKernelWithShimVendorCert",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
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
										Image:    FileOSComponent("testdata/mock.efi.signed.2")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.2"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}}},
			digests: tpm2.DigestList{
				tpm2.Digest{0x4a, 0x4f, 0xd9, 0x0c, 0x84, 0x18, 0xbc, 0x4e, 0x6c, 0x76, 0x3a,
					0xcc, 0x6d, 0x88, 0x49, 0xfd, 0xd9, 0x97, 0xce, 0xaf, 0xba, 0xfe, 0x83,
					0x53, 0x8c, 0x50, 0x7d, 0xaf, 0x16, 0x5a, 0xe8, 0xe6}},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// and the kernel are verified by shim's vendor cert
			desc:    "VerifyFromDbUC20_2",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: &SealParams{
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
										Image:    FileOSComponent("testdata/mock.efi.signed.2")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.2"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.2")}}}}}}}}},
			digests: tpm2.DigestList{
				tpm2.Digest{0x49, 0xa9, 0xa7, 0x54, 0xdc, 0xc9, 0x2a, 0xe1, 0x41, 0x09, 0x9d,
					0xdf, 0xe5, 0xc1, 0xa1, 0xb0, 0xee, 0xab, 0xfa, 0x39, 0x83, 0xcb, 0x7b,
					0x7a, 0xef, 0x52, 0x11, 0x39, 0x81, 0x7b, 0xc9, 0x76}},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// is verified by shim's vendor cert and the kernel is verified by the UEFI db
			desc:    "VerifyFromDbUC20_3",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
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
										Image:    FileOSComponent("testdata/mock.efi.signed.1")},
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.2"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}}},
			digests: tpm2.DigestList{
				tpm2.Digest{0xf7, 0x3b, 0xb2, 0x4f, 0x88, 0xba, 0x33, 0xe9, 0xa9, 0x96, 0x88,
					0xbb, 0x47, 0xe7, 0x2e, 0xdd, 0x79, 0x8f, 0x24, 0x42, 0xc8, 0xe0, 0x72,
					0xe0, 0xde, 0x03, 0xcd, 0xe9, 0xed, 0xbb, 0xf3, 0x94}},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. Two
			// kernels are supplied for both normal and recovery paths signed with alternate keys
			desc:    "KernelKeyRotationUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
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
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81},
				tpm2.Digest{0xa6, 0x40, 0x25, 0x48, 0x44, 0x24, 0xba, 0x7a, 0x64, 0xdc, 0x11,
					0x54, 0x88, 0x9e, 0xb8, 0xfe, 0x78, 0xd7, 0xb2, 0x04, 0xfa, 0x58, 0x1a,
					0xce, 0x55, 0x52, 0x2c, 0x07, 0x40, 0x50, 0xe4, 0x28}},
		},
		{
			// Verify that DirectLoadWithShimVerify fails if there are no shim binaries in the boot chain.
			desc:    "MissingShimVendorCertSection",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mock.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}},
			err: "cannot process events from event log: cannot process KEK measurement event: cannot process KEK measurement event 0: " +
				"cannot process subsequent events from event log: cannot process db measurement event: cannot process db measurement event 0: " +
				"cannot process subsequent events from event log: cannot process dbx measurement event: cannot process dbx measurement event " +
				"0: cannot process subsequent events from event log: cannot compute OS load events: cannot compute events for component at " +
				"index 0 (testdata/mock.efi.signed.1): cannot process executable: cannot compute events for subsequent components: cannot " +
				"compute events for component at index 0 (testdata/mock.efi.signed.1): cannot process executable: cannot compute measurement " +
				"for PE binary verification: shim verification specified without being preceeded by a shim executable",
		},
		{
			// Test that shim binaries without a vendor cert work correctly
			desc:    "NoShimVendorCert",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}},
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81}},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. The
			// normal and recovery chains have different trust paths
			desc:    "MismatchedNormalAndRecoverySystemsUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
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
										Image:    FileOSComponent("testdata/mock.efi.signed.2"),
										Next: []*OSComponent{
											&OSComponent{
												LoadType: DirectLoadWithShimVerify,
												Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}}}}},
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81},
				tpm2.Digest{0xa6, 0x40, 0x25, 0x48, 0x44, 0x24, 0xba, 0x7a, 0x64, 0xdc, 0x11,
					0x54, 0x88, 0x9e, 0xb8, 0xfe, 0x78, 0xd7, 0xb2, 0x04, 0xfa, 0x58, 0x1a,
					0xce, 0x55, 0x52, 0x2c, 0x07, 0x40, 0x50, 0xe4, 0x28}},
		},
		{
			desc:    "DbxUpdate",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}},
				SecureBootDbKeystores: []string{"testdata/updates"}},
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81},
				tpm2.Digest{0x38, 0xae, 0x1e, 0x75, 0xea, 0x72, 0x37, 0x98, 0x3f, 0x4d, 0x44, 0xc3,
					0x69, 0x5e, 0x08, 0xa1, 0xd7, 0xb6, 0x0d, 0x8c, 0xba, 0xc3, 0xc6, 0x5e,
					0x57, 0x64, 0x73, 0xb7, 0x27, 0x77, 0x61, 0x6e}},
		},
		{
			desc:    "DbAndDbxUpdate",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: &SealParams{
				LoadPaths: []*OSComponent{
					&OSComponent{
						LoadType: FirmwareLoad,
						Image:    FileOSComponent("testdata/mockshim1.efi.signed.1"),
						Next: []*OSComponent{
							&OSComponent{
								LoadType: DirectLoadWithShimVerify,
								Image:    FileOSComponent("testdata/mock.efi.signed.1"),
								Next: []*OSComponent{
									&OSComponent{
										LoadType: DirectLoadWithShimVerify,
										Image:    FileOSComponent("testdata/mock.efi.signed.1")}}}}}},
				SecureBootDbKeystores: []string{"testdata/updates3"}},
			digests: tpm2.DigestList{
				tpm2.Digest{0xe8, 0x01, 0x30, 0xf2, 0xd8, 0x21, 0x2d, 0x69, 0x69, 0xf0, 0xcd,
					0x20, 0xef, 0xfc, 0x3b, 0xbd, 0xed, 0x14, 0x58, 0x48, 0x61, 0xf8, 0xf5,
					0x60, 0xfb, 0xc5, 0x20, 0x8a, 0x8b, 0xfc, 0x06, 0x81},
				tpm2.Digest{0x38, 0xae, 0x1e, 0x75, 0xea, 0x72, 0x37, 0x98, 0x3f, 0x4d, 0x44, 0xc3,
					0x69, 0x5e, 0x08, 0xa1, 0xd7, 0xb6, 0x0d, 0x8c, 0xba, 0xc3, 0xc6, 0x5e,
					0x57, 0x64, 0x73, 0xb7, 0x27, 0x77, 0x61, 0x6e},
				tpm2.Digest{0x3d, 0x61, 0x2a, 0x0e, 0xda, 0x6d, 0xeb, 0x41, 0x98, 0x2b, 0x81, 0xd4,
					0xc2, 0x46, 0x95, 0xcf, 0x72, 0x1e, 0x00, 0x23, 0x3b, 0x40, 0x48, 0x9a,
					0xf5, 0x91, 0x8d, 0xae, 0x86, 0x53, 0x20, 0xac}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			resetTPMSimulator(t, tpm, tcti)
			replayLogToTPM(t, tpm, tcti, data.logPath)

			eventLogPathForTesting = data.logPath
			efivarsPathForTesting = data.efivars
			defer func() {
				eventLogPathForTesting = ""
				efivarsPathForTesting = ""
			}()

			digests, err := computeSecureBootPolicyDigests(tpm.TPMContext, tpm2.HashAlgorithmSHA256, data.params)
			if data.err != "" {
				if err == nil {
					t.Fatalf("Expected computeSecureBootPolicyDigests to fail")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("computeSecureBootPolicyDigests failed: %v", err)
				}

				if len(digests) != len(data.digests) {
					t.Fatalf("Unexpected number of digests")
				}
				for i, digest := range digests {
					if !bytes.Equal(digest, data.digests[i]) {
						t.Errorf("Unexpected digest (got %x, expected %x)", digest,
							data.digests[i])
					}
				}
			}
		})
	}
}
