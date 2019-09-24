package main

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	winCertTypePKCSSignedData uint16 = 2
)

func run() error {
	if len(flag.Args()) < 1 {
		return errors.New("Missing filename")
	}

	f, err := os.Open(flag.Args()[0])
	if err != nil {
		return fmt.Errorf("Cannot open file: %v", err)
	}
	defer f.Close()

	pefile, err := pe.NewFile(f)
	if err != nil {
		return fmt.Errorf("Cannot decode PE binary: %v", err)
	}

	var dd *pe.DataDirectory
	switch oh := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes < 5 {
			return errors.New("cannot obtain security directory entry: invalid number of data " +
				"directories")
		}
		dd = &oh.DataDirectory[4]
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes < 5 {
			return errors.New("cannot obtain security directory entry: invalid number of data " +
				"directories")
		}
		dd = &oh.DataDirectory[4]
	default:
		return errors.New("cannot obtain security directory entry: no optional header")
	}

	secReader := io.NewSectionReader(f, int64(dd.VirtualAddress), int64(dd.Size))

	var dwLength uint32
	if err := binary.Read(secReader, binary.LittleEndian, &dwLength); err != nil {
		return fmt.Errorf("cannot read signature length: %v", err)
	}
	if _, err := secReader.Seek(2, io.SeekCurrent); err != nil {
		return fmt.Errorf("cannot advance beyond signature revision level: %v", err)
	}
	var wCertificateType uint16
	if err := binary.Read(secReader, binary.LittleEndian, &wCertificateType); err != nil {
		return fmt.Errorf("cannot read signature type: %v", err)
	}
	if wCertificateType != winCertTypePKCSSignedData {
		return fmt.Errorf("unexpected value %d for wCertificateType: not an Authenticode signature",
			wCertificateType)
	}
	data := make([]byte, dwLength-8)
	if _, err := io.ReadFull(secReader, data); err != nil {
		return fmt.Errorf("cannot read signature: %v", err)
	}

	if _, err := os.Stdout.Write(data); err != nil {
		return fmt.Errorf("cannot write to stdout: %v", err)
	}

	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
