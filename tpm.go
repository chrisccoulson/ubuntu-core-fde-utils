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
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/snapcore/snapd/httputil"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"
)

const (
	tpmPath string = "/dev/tpm0"

	ekCertHandle tpm2.Handle = 0x01c00002
)

func readEkCert(tpm *tpm2.TPMContext, ownerAuth []byte) (*x509.Certificate, error) {
	ekCertIndex, err := tpm.WrapHandle(ekCertHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context: %w", err)
	}

	ekCertPub, _, err := tpm.NVReadPublic(ekCertIndex)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of index: %w", err)
	}

	tryRead := func(authContext tpm2.ResourceContext, session *tpm2.Session) (*x509.Certificate, error) {
		data, err := tpm.NVRead(authContext, ekCertIndex, ekCertPub.Size, 0, session)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(data)
	}

	if ekCertPub.Attrs&tpm2.AttrNVAuthRead > 0 {
		if cert, err := tryRead(ekCertIndex, nil); err != nil {
			if !isAuthFailError(err) {
				return nil, xerrors.Errorf("cannot read index: %w", err)
			} else if ekCertPub.Attrs&tpm2.AttrNVOwnerRead == 0 {
				return nil, tpm2.ResourceUnavailableError{ekCertHandle}
			}
		} else {
			return cert, nil
		}
	}

	owner, _ := tpm.WrapHandle(tpm2.HandleOwner)
	sessionContext, err := tpm.StartAuthSession(nil, owner, tpm2.SessionTypeHMAC, nil, defaultHashAlgorithm, ownerAuth)
	if err != nil {
		return nil, xerrors.Errorf("cannot start session: %w", err)
	}
	defer tpm.FlushContext(sessionContext)

	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrContinueSession, AuthValue: ownerAuth}
	cert, err := tryRead(ekCertIndex, &session)
	if err != nil {
		return nil, xerrors.Errorf("cannot read index: %w", err)
	}

	return cert, nil
}

func fetchIntermediates(cert *x509.Certificate) ([]*x509.Certificate, error) {
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, nil
	}

	client := httputil.NewHTTPClient(&httputil.ClientOptions{Timeout: 10 * time.Second})
	var out []*x509.Certificate

	for {
		if len(cert.IssuingCertificateURL) == 0 {
			return nil, fmt.Errorf("cannot download issuer of %v: no issuer URLs", cert.Subject)
		}

		var parent *x509.Certificate

		tryUrl := func(url string) (*x509.Certificate, error) {
			resp, err := client.Get(url)
			if err != nil {
				return nil, xerrors.Errorf("GET request failed: %w", err)
			}
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, xerrors.Errorf("cannot read body: %w", err)
			}
			cert, err := x509.ParseCertificate(body)
			if err != nil {
				return nil, xerrors.Errorf("cannot parse certificate: %w", err)
			}
			return cert, nil
		}

		var err error
		for i, issuerUrl := range cert.IssuingCertificateURL {
			p, e := tryUrl(issuerUrl)
			if e != nil {
				if i == len(cert.IssuingCertificateURL)-1 {
					err = xerrors.Errorf("cannot obtain issuing certificate from %s: %w", issuerUrl, e)
				}
				continue
			}
			parent = p
			break
		}

		if parent == nil {
			return nil, xerrors.Errorf("cannot download issuer of %v: %w", cert.Subject, err)
		}

		if bytes.Equal(parent.RawIssuer, parent.RawSubject) {
			break
		}

		out = append(out, parent)
		cert = parent
	}

	return out, nil
}

// FetchAndSaveEkIntermediateCerts attempts to download intermediate certificates for the endorsement certificate obtained from
// the TPM associated with the tpm parameter. The endorsement certificate usually doesn't require an authorization value to
// obtain it from the TPM, but if the initial attempt to read it fails then this function will attempt to read it from the TPM
// using the storage hierarchy authorization as a fallback, which should be provided by ownerAuth.
//
// On success, the intermediate certificates are saved to the file referenced by dest in a form that can be read by
// SecureConnectToDefaultTPM and SecureConnectToDefaultUnprovisionedTPM.
func FetchAndSaveEkIntermediateCerts(tpm *tpm2.TPMContext, dest string, ownerAuth []byte) error {
	cert, err := readEkCert(tpm, ownerAuth)
	if err != nil {
		if isAuthFailError(err) {
			return ErrOwnerAuthFail
		}
		return xerrors.Errorf("cannot obtain endorsement certificate from TPM: %w", err)
	}

	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	intermediates, err := fetchIntermediates(cert)
	if err != nil {
		return xerrors.Errorf("cannot obtain intermediate certificates for %s: %w", cert.Subject, err)
	}

	rawCerts := make([][]byte, 0, len(intermediates))
	for _, c := range intermediates {
		rawCerts = append(rawCerts, c.Raw)
	}

	if err := tpm2.MarshalToWriter(f, rawCerts); err != nil {
		return xerrors.Errorf("cannot marshal intermediate certificates: %w", err)
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot atomically replace file: %w", err)
	}

	return nil
}

func ConnectToDefaultTPM() (*tpm2.TPMContext, error) {
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM device: %v", err)
	}

	tpm, _ := tpm2.NewTPMContext(tcti)
	return tpm, nil
}
