package fdeutil

import (
	"bytes"
	"crypto/x509"
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
			path: "testdata/db1.bin",
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
			path: "testdata/db2.bin",
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
			path: "testdata/db3.bin",
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
			path: "testdata/dbx1.bin",
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
			path:       "testdata/dbx2.bin",
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
				eventClassUnclassified,
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

func replayLogToTPM(t *testing.T, tpm *tpm2.TPMContext, tcti *tpm2.TctiMssim, logPath string) {
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
			digests = append(digests,
				tpm2.TaggedHash{HashAlg: tpm2.AlgorithmId(alg), Digest: tpm2.Digest(digest)})
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
		dbPath  string
		dbxPath string
		params  *SealParams
		digests tpm2.DigestList
		err     string
	}{
		{
			desc:    "VerifyFromDbClassic",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "VerifyDirectCASignature",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "VerifyFromDbUC20",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "InvalidGrubSignature",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			err: "cannot process events from event log: cannot process db measurement event with " +
				"current db contents: cannot process subsequent events from event log: cannot " +
				"process dbx measurement event with current dbx contents: cannot process " +
				"subsequent events from event log: cannot compute OS load events: cannot " +
				"compute events for component at index 0: cannot process Shim executable: " +
				"cannot compute events for subsequent components: cannot compute events for " +
				"component at index 0: cannot process executable: cannot compute measurement " +
				"for PE binary verification: no root certificate found",
		},
		{
			desc:    "NoKernelSignature",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			err: "cannot process events from event log: cannot process db measurement event with " +
				"current db contents: cannot process subsequent events from event log: cannot " +
				"process dbx measurement event with current dbx contents: cannot process " +
				"subsequent events from event log: cannot compute OS load events: cannot " +
				"compute events for component at index 0: cannot process Shim executable: " +
				"cannot compute events for subsequent components: cannot compute events for " +
				"component at index 0: cannot process executable: cannot compute events for " +
				"subsequent components: cannot compute events for component at index 0: cannot " +
				"process executable: cannot compute measurement for PE binary verification: " +
				"cannot read signature length: EOF",
		},
		{
			desc:    "ShimVerificationDisabled",
			logPath: "testdata/eventlog2.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "VerifyGrubAndKernelWithShimVendorCert",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "VerifyFromDbUC20_2",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db3.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "VerifyFromDbUC20_3",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "KernelKeyRotationUC20",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "MissingShimVendorCertSection",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			err: "cannot process events from event log: cannot process db measurement event with " +
				"current db contents: cannot process subsequent events from event log: cannot " +
				"process dbx measurement event with current dbx contents: cannot process " +
				"subsequent events from event log: cannot compute OS load events: cannot " +
				"compute events for component at index 0: cannot process executable: cannot " +
				"compute events for subsequent components: cannot compute events for component " +
				"at index 0: cannot process executable: cannot compute measurement for PE " +
				"binary verification: shim verification specified without being preceeded by a " +
				"shim executable",
		},
		{
			desc:    "NoShimVendorCert",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
			desc:    "MismatchedNormalAndRecoverySystemsUC20",
			logPath: "testdata/eventlog1.bin",
			dbPath:  "testdata/db2.bin",
			dbxPath: "testdata/dbx2.bin",
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
	} {
		t.Run(data.desc, func(t *testing.T) {
			resetTPMSimulator(t, tpm, tcti)
			replayLogToTPM(t, tpm, tcti, data.logPath)

			eventLogPathForTesting = data.logPath
			dbPathForTesting = data.dbPath
			dbxPathForTesting = data.dbxPath
			defer func() {
				eventLogPathForTesting = ""
				dbPathForTesting = ""
				dbxPathForTesting = ""
			}()

			digests, err := computeSecureBootPolicyDigests(tpm, tpm2.AlgorithmSHA256, data.params)
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
