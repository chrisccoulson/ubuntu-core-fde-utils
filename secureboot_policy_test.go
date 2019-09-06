package fdeutil

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

var (
	microsoftRootCANameDER = []byte{0x30, 0x81, 0x88, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
		0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x57,
		0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
		0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31, 0x1e, 0x30, 0x1c, 0x06,
		0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20,
		0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x32, 0x30, 0x30, 0x06,
		0x03, 0x55, 0x04, 0x03, 0x13, 0x29, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20,
		0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
		0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x32, 0x30, 0x31, 0x30}
	microsoftOwnerGuid = tcglog.EFIGUID{0x77fa9abd, 0x0359, 0x4d32, 0xbd60,
		[...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}}
)

func TestDecodeSecureBootDb(t *testing.T) {
	type certId struct {
		issuer []byte
		subject string
		serial []byte
		owner tcglog.EFIGUID
	}
	for _, data := range []struct {
		desc string
		path string
		certs []certId
	}{
		{
			desc: "db1",
			path: "testdata/db1.bin",
			certs: []certId{
				{
					issuer: microsoftRootCANameDER,
					subject: "CN=Microsoft Windows Production PCA 2011,O=Microsoft "+
						"Corporation,L=Redmond,ST=Washington,C=US",
					serial: []byte{0x61, 0x07, 0x76, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
					owner: microsoftOwnerGuid,
				},
				{
					issuer: []byte{0x30, 0x81, 0x91, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
						0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
						0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69,
						0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
						0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e,
						0x64, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
						0x15, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20,
						0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
						0x31, 0x3b, 0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x32,
						0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x43,
						0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
						0x54, 0x68, 0x69, 0x72, 0x64, 0x20, 0x50, 0x61, 0x72, 0x74, 0x79,
						0x20, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x70, 0x6c, 0x61, 0x63,
						0x65, 0x20, 0x52, 0x6f, 0x6f, 0x74},
					subject: "CN=Microsoft Corporation UEFI CA 2011,O=Microsoft Corporation,"+
						"L=Redmond,ST=Washington,C=US",
					serial: []byte{0x61, 0x08, 0xd3, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
					owner: microsoftOwnerGuid,
				},
			},
		},
		{
			desc: "dbx1",
			path: "testdata/dbx1.bin",
			certs: []certId{
				{
					issuer: microsoftRootCANameDER,
					subject: "CN=Microsoft Windows PCA 2010,O=Microsoft Corporation,"+
						"L=Redmond,ST=Washington,C=US",
					serial: []byte{0x61, 0x0c, 0x6a, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
					owner: tcglog.EFIGUID{0x00000000, 0x0000, 0x0000, 0x0000,
						[...]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				},
			},
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

			certs, err := decodeSecureBootDb(d[4:])
			if err != nil {
				t.Fatalf("decodeSecureBootDb failed: %v", err)
			}
			if len(certs) != len(data.certs) {
				t.Fatalf("Unexpected number of certificates")
			}
			for i, c := range certs {
				if c.owner != data.certs[i].owner {
					t.Errorf("Unexpected owner (got %s, expected %s)", &c.owner,
						&data.certs[i].owner)
				}
				if !bytes.Equal(c.cert.RawIssuer, data.certs[i].issuer) {
					t.Errorf("Unexpected issuer: %s", c.cert.Issuer)
				}
				if c.cert.Subject.String() != data.certs[i].subject {
					t.Errorf("Unexpected subject: %s", c.cert.Subject.String())
				}
				if !bytes.Equal(c.cert.SerialNumber.Bytes(), data.certs[i].serial) {
					t.Errorf("Unexpected serial number (got %x, expected %x)",
						c.cert.SerialNumber.Bytes(), data.certs[i].serial)
				}
			}
		})
	}
}

func TestClassifySecureBootEvents(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct{
		desc string
		logPath string
		classifications []eventClass
		err string
	}{
		{
			desc: "SecureBootEnabled",
			logPath: "testdata/eventlog1.bin",
			classifications: []eventClass{
				eventClassUnclassified,
				eventClassUnclassified,
				eventClassUnclassified,
				eventClassDb,
				eventClassDbx,
				eventClassUnclassified,
				eventClassShim,
				eventClassGrub,
				eventClassKernel},
		},
		{
			desc: "ShimValidationDisabled",
			logPath: "testdata/eventlog2.bin",
			err: "this boot was performed with validation disabled in Shim",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			f, err := os.Open(data.logPath)
			if err != nil {
				t.Fatalf("Open failed: %v\n", err)
			}

			// In order to test classifySecureBootEvents, we need to validate the log first. In order
			// to validate the log, we need the TPM to be consistent with the log. This is why this
			// test depends on the simulator, so we can reset it now and replay the log in to the TPM
			resetTPMSimulator(t, tpm, tcti)

			log, err := tcglog.NewLogFromFile(f, tcglog.LogOptions{})
			if err != nil {
				t.Fatalf("NewLogFromFile failed: %v", err)
			}

			for {
				event, err := log.NextEvent()
				if err != nil {
					if err == io.EOF {
						break
					}
					t.Fatalf("NextEvent failed: %v", err)
				}

				digests := tpm2.TaggedHashList{
					tpm2.TaggedHash{HashAlg: tpm2.AlgorithmSHA256,
						Digest: event.Digests[tcglog.AlgorithmSha256]}}
				if err := tpm.PCRExtend(tpm2.Handle(event.Index), digests, nil); err != nil {
					t.Fatalf("PCRExtend failed: %v", err)
				}
			}

			validatedLog, err := tcglog.ValidateLogAgainstTPM(tpm, data.logPath,
				tcglog.LogValidateOptions{PCRs: []tcglog.PCRIndex{secureBootPCR},
					Algorithms: []tcglog.AlgorithmId{tcglog.AlgorithmSha256}})
			if err != nil {
				t.Fatalf("ValidateLogAgainstTPM failed: %v", err)
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
