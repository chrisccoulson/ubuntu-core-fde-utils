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
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/intel-go/cpuid"
	"github.com/snapcore/snapd/httputil"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"
)

const (
	tpmPath string = "/dev/tpm0"

	ekCertHandle tpm2.Handle = 0x01c00002
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTCGEkCertificate       = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
)

// TPMConnection corresponds to a connection to a TPM device, and is a wrapper around *tpm2.TPMContext.
type TPMConnection struct {
	*tpm2.TPMContext
	verifiedEkCertChain []*x509.Certificate
	ekContext           tpm2.ResourceContext
	hmacSession         tpm2.ResourceContext
}

// VerifiedEkCertChain returns the verified endorsement certificate chain for the endorsement certificate obtained from
// this TPM. It was verified using one of the built-in TPM manufacturer root CAs
func (t *TPMConnection) VerifiedEkCertChain() []*x509.Certificate {
	return t.verifiedEkCertChain
}

// EkContext returns a reference to the TPM's endorsement key, if one exists. If the endorsement certificate has been verified,
// the returned ResourceContext will correspond to the key for which the certificate was issued.
func (t *TPMConnection) EkContext() (tpm2.ResourceContext, error) {
	if t.ekContext == nil || t.ekContext.Handle() == tpm2.HandleUnassigned {
		return nil, ErrProvisioning
	}
	return t.ekContext, nil
}

// HmacSession returns a HMAC session instance which was created to verify that the TPM contains the sensitive area of the endorsement
// key (accessible from TPMConnection.EkContext), and is therefore the TPM for which the endorsement certificate was issued. It is
// retained in order to reduce the number of sessions that need to be created during unseal operations, and is created with a
// symmetric algorithm for parameter encryption.
func (t *TPMConnection) HmacSession() (*tpm2.Session, error) {
	if t.hmacSession == nil || t.hmacSession.Handle() == tpm2.HandleUnassigned {
		return nil, ErrProvisioning
	}
	return &tpm2.Session{Context: t.hmacSession, Attrs: tpm2.AttrContinueSession}, nil
}

func (t *TPMConnection) Close() error {
	t.FlushContext(t.hmacSession)
	return t.TPMContext.Close()
}

type verificationError struct {
	err error
}

func (e verificationError) Error() string {
	return e.err.Error()
}

func (t *TPMConnection) unsafeAcquireEkContext() error {
	ekContext, err := t.WrapHandle(ekHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for endorsement key: %w", err)
	}

	if ok, err := isObjectPrimaryKeyWithTemplate(t.TPMContext, tpm2.HandleEndorsement, ekContext, &ekTemplate, nil); err != nil {
		return xerrors.Errorf("cannot determine if object is a primary key in the endorsement hierarchy: %w", err)
	} else if !ok {
		return verificationError{errors.New("object is not a valid endorsement key")}
	}

	t.ekContext = ekContext
	return nil
}

func (t *TPMConnection) safeAcquireEkContext() error {
	// To salt a session with a value that's only recoverable by the TPM for which the endorsement certificate was issued, we need
	// a ResourceContext for the corresponding endorsement key associated with that certificate to pass to TPMContext.StartAuthSession.
	// TPMContext.StartAuthSession uses the public area of the associated object which is read back from the TPM to encrypt the salt.
	// This means that we need to verify that the public area read back from the TPM inside go-tpm2 matches the object for which
	// the endorsement certificate was issued.

	// Obtain a ResourceContext for the object resident in the endorsement key's slot on the TPM. Under the hood, go-tpm2 initializes
	// the ResourceContext with TPM2_ReadPublic here, and cross-checks that the returned name and public area match. The returned
	// name is available via ResourceContext.Name and the returned public area is retained by the ResourceContext and used to share
	// secrets with the TPM.
	ekContext, err := t.WrapHandle(ekHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for endorsement key: %w", err)
	}

	if ok, err := isObjectPrimaryKeyWithTemplate(t.TPMContext, tpm2.HandleEndorsement, ekContext, &ekTemplate, nil); err != nil {
		return xerrors.Errorf("cannot determine if object is a primary key in the endorsement hierarchy: %w", err)
	} else if !ok {
		// This is a bit hacky, but this error type is caught in SecureConnectToDefaultTPM and turned in to a ErrProvisioning
		// error, which makes sense.
		return xerrors.Errorf("cannot obtain context for a valid endorsement key: %w", tpm2.ResourceUnavailableError{Handle: ekHandle})
	}

	cert := t.verifiedEkCertChain[0]

	// Obtain the RSA public key from the endorsement certificate

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("cannot obtain RSA public key from *x509.Certificate")
	}

	// Insert the RSA public key in to the EK template to compute the name of the EK object we expected to read back from the TPM.
	var ekPublic *tpm2.Public
	b, _ := tpm2.MarshalToBytes(ekTemplate)
	tpm2.UnmarshalFromBytes(b, &ekPublic)

	if pubKey.E != 65537 {
		ekPublic.Params.RSADetail().Exponent = uint32(pubKey.E)
	}
	ekPublic.Unique.Data = tpm2.PublicKeyRSA(pubKey.N.Bytes())

	expectedEkName, err := ekPublic.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute expected name of verified EK object: %w", err)
	}

	// Verify that the public area associated with the endorsement key ResourceContext which was read from the TPM is the one that the
	// endorsement certificate was issued for. We do this by comparing its name with the one we computed from the EK template with the
	// certificate's public key inserted in to it (remember that go-tpm2 has already verified that the name that was read back is
	// consistent with the public area).
	if !bytes.Equal(ekContext.Name(), expectedEkName) {
		// An exponent of 0 in the public area corresponds to the default (65537) exponent, but some TPM's don't return 0 in the
		// public area (my Nuvoton TPM, for example). If the initial name comparison with exponent == 0 failed, try exponent == 65537.
		ekPublic.Params.RSADetail().Exponent = uint32(pubKey.E)
		expectedEkName, err := ekPublic.Name()
		if err != nil {
			return xerrors.Errorf("cannot compute expected name of verified EK object: %w", err)
		}
		if !bytes.Equal(ekContext.Name(), expectedEkName) {
			return verificationError{errors.New("endorsement key returned from the TPM doesn't match the endorsement certificate")}
		}
	}

	// At this point, we've verified that ekContext references the public area associated with the public key of the endorsement
	// certificate, and can therefore safely be used to encrypt secrets that can only be decrypted on the TPM for which the endorsement
	// certificate was issued.

	t.ekContext = ekContext
	return nil
}

func (t *TPMConnection) acquireEkContextAndVerifyTPM() error {
	if t.hmacSession != nil && t.hmacSession.Handle() != tpm2.HandleUnassigned {
		if err := t.FlushContext(t.hmacSession); err != nil {
			return xerrors.Errorf("cannot flush existing HMAC session: %w", err)
		}
	}

	if len(t.verifiedEkCertChain) > 0 {
		if err := t.safeAcquireEkContext(); err != nil {
			return err
		}
	} else if err := t.unsafeAcquireEkContext(); err != nil {
		return err
	}

	// Verify that the TPM we're connected to is the one that the endorsement certificate was issued for (if we've validated it) by
	// creating a session that's salted with a value protected by the public part of the endorsement key, using that to integrity protect
	// a command and verifying we get a valid response. The salt (and therefore the session key) can only be recovered on and used by the
	// TPM for which the endorsement certificate was issued, so a correct response means we're communicating with that TPM.
	symmetric := tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   tpm2.SymKeyBitsU{Data: uint16(128)},
		Mode:      tpm2.SymModeU{Data: tpm2.SymModeCFB}}
	sessionContext, err := t.StartAuthSession(t.ekContext, nil, tpm2.SessionTypeHMAC, &symmetric, defaultHashAlgorithm, nil)
	if err != nil {
		return xerrors.Errorf("cannot create HMAC session: %w", err)
	}
	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		t.FlushContext(sessionContext)
	}()

	if len(t.verifiedEkCertChain) > 0 {
		session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrContinueSession | tpm2.AttrAudit}
		_, err = t.GetRandom(20, &session)
		if err != nil {
			if isAuthFailError(err) {
				return verificationError{errors.New("the TPM can't prove it is the device that the endorsement certificate belongs to")}
			}
			return xerrors.Errorf("cannot execute command to verify that the TPM is genuine: %w", err)
		}
	}

	succeeded = true

	t.hmacSession = sessionContext
	return nil
}

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
				return nil, tpm2.ResourceUnavailableError{Handle: ekCertHandle}
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

func checkChainForEkCertUsage(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}

NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageAny {
				continue NextCert
			}
		}

		for _, usage := range cert.UnknownExtKeyUsage {
			if usage.Equal(oidTCGEkCertificate) {
				continue NextCert
			}
		}

		return false
	}

	return true
}

func verifyEkCertificate(cert *x509.Certificate, roots, intermediates *x509.CertPool) ([]*x509.Certificate, error) {
	// Verify certificate for any usage
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	candidates, err := cert.Verify(opts)
	if err != nil {
		return nil, err
	}

	// Make sure we have a chain that permits the tcg-kg-EKCertificate extended key usage
	var chain []*x509.Certificate
	for _, c := range candidates {
		if checkChainForEkCertUsage(c) {
			chain = c
			break
		}
	}

	if chain == nil {
		return nil, errors.New("not a valid EK certificate")
	}

	return chain, nil
}

var openDefaultTcti = func() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPMDevice(tpmPath)
}

func connectToDefaultTPM() (*tpm2.TPMContext, error) {
	tcti, err := openDefaultTcti()
	if err != nil {
		return nil, xerrors.Errorf("cannot open TPM device: %w", err)
	}

	tpm, _ := tpm2.NewTPMContext(tcti)
	return tpm, nil
}

type intermediateCertsError struct {
	err error
}

func (e intermediateCertsError) Error() string {
	return e.err.Error()
}

func connectToDefaultTPMAndVerifyEkCert(ekIntermediateCertsFile string, ownerAuth []byte) (*tpm2.TPMContext, []*x509.Certificate, error) {
	// Load and parse intermediate certificates, if provided
	intermediates := x509.NewCertPool()
	if ekIntermediateCertsFile != "" {
		f, err := os.Open(ekIntermediateCertsFile)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot open intermediate certs file: %w", err)
		}
		defer f.Close()
		var data [][]byte
		if err := tpm2.UnmarshalFromReader(f, &data); err != nil {
			return nil, nil, intermediateCertsError{err}
		}
		for _, d := range data {
			cert, err := x509.ParseCertificate(d)
			if err != nil {
				return nil, nil, intermediateCertsError{err}
			}
			intermediates.AddCert(cert)
		}
	}

	tpm, err := connectToDefaultTPM()
	if err != nil {
		return nil, nil, err
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.Close()
	}()

	// Obtain the EK certificate from the TPM
	cert, err := readEkCert(tpm, ownerAuth)
	if err != nil {
		var unavailErr tpm2.ResourceUnavailableError
		if xerrors.As(err, &unavailErr) {
			return nil, nil, verificationError{errors.New("cannot obtain endorsement certificate from TPM")}
		}
		return nil, nil, xerrors.Errorf("cannot obtain endorsement certificate from TPM: %w", err)
	}

	// Parse the built-in roots
	roots := x509.NewCertPool()
	for _, data := range rootCAs {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			panic(fmt.Sprintf("cannot parse root CA: %v", err))
		}
		roots.AddCert(cert)
	}

	// If SAN contains only unhandled fields, it ends up here. Remove it and handle it ourselves below
	// TODO: Parse the SAN data
	for i, e := range cert.UnhandledCriticalExtensions {
		if e.Equal(oidSubjectAlternativeName) {
			copy(cert.UnhandledCriticalExtensions[i:], cert.UnhandledCriticalExtensions[i+1:])
			cert.UnhandledCriticalExtensions = cert.UnhandledCriticalExtensions[:len(cert.UnhandledCriticalExtensions)-1]
			break
		}
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		return nil, nil, verificationError{errors.New("endorsement certificate contains a public key with the wrong algorithm")}
	}

	// Perform verification of the EK cert
	chain, err := verifyEkCertificate(cert, roots, intermediates)
	if err != nil {
		return nil, nil, verificationError{err}
	}

	// At this point, we've verified that the endorsent certificate has the correct properties and was issued by a trusted TPM
	// manufacturer, and is therefore a valid assertion by that manufacturer that the contained public key is associated with a
	// properly formed endorsement key with the expected properties (restricted, non-duplicable decrypt key), generated from a
	// private seed injected in to a genuine TPM by them. Secrets encrypted by this public key can only be decrypted by and used
	// on the TPM for which this certificate was issued.

	succeeded = true
	return tpm, chain, nil
}

// FetchAndSaveEkIntermediateCerts attempts to download intermediate certificates for the endorsement certificate obtained from
// the TPM associated with the tpm parameter. The endorsement certificate usually doesn't require an authorization value to
// obtain it from the TPM, but if the initial attempt to read it fails then this function will attempt to read it from the TPM
// using the storage hierarchy authorization as a fallback, which should be provided by ownerAuth.
//
// On success, the intermediate certificates are saved to the file referenced by dest in a form that can be read by
// SecureConnectToDefaultTPM and SecureConnectToDefaultUnprovisionedTPM.
func FetchAndSaveEkIntermediateCerts(tpm *TPMConnection, dest string, ownerAuth []byte) error {
	cert, err := readEkCert(tpm.TPMContext, ownerAuth)
	if err != nil {
		if isAuthFailError(err) {
			return AuthFailError{tpm2.HandleOwner}
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

// ConnectToDefaultTPM will attempt to connect to the default TPM. This function makes no attempt to verify the authenticity of the
// TPM and does not require the TPM to have a manufacturer installed endorsement certificate.
func ConnectToDefaultTPM() (*TPMConnection, error) {
	tpm, err := connectToDefaultTPM()
	if err != nil {
		return nil, err
	}

	t := &TPMConnection{TPMContext: tpm}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		t.Close()
	}()

	if err := t.acquireEkContextAndVerifyTPM(); err != nil {
		var unavailErr tpm2.ResourceUnavailableError
		var verifyErr verificationError
		if !xerrors.As(err, &unavailErr) && !xerrors.As(err, &verifyErr) {
			return nil, xerrors.Errorf("cannot acquire public area of the endorsement key and verify the TPM: %w", err)
		}
	}

	succeeded = true
	return t, nil
}

// SecureConnectToDefaultUnprovisionedTPM will attempt to connect to the default TPM and then verify the TPM's manufacturer issued
// endorsement certificate if it exists. The ekIntermediateCertsFile argument should point to a file created previously by
// FetchAndSaveEkIntermediateCerts. The endorsement certificate usually doesn't require an authorization value to obtain it from the
// TPM, but if the initial attempt to read it fails then this function will attempt to read it from the TPM using the storage
// hierarchy authorization as a fallback, which should be provided by ownerAuth.
//
// This function doesn't verify that the TPM is the one that the endorsement certificate was issued for. It is designed to be used
// on a TPM before ProvisionTPM has been called, or on a TPM that doesn't have a persistent endorsement key at the expected location.
//
// If the file referenced by ekIntermediateCertsFile cannot be loaded, a InvalidIntermediateCertsFileError error will be returned.
//
// If verification of the endorsement certificate fails or it doesn't exist at the expected location, a TPMVerificationError error
// will be returned.
func SecureConnectToDefaultUnprovisionedTPM(ekIntermediateCertsFile string, ownerAuth []byte) (*TPMConnection, error) {
	tpm, chain, err := connectToDefaultTPMAndVerifyEkCert(ekIntermediateCertsFile, ownerAuth)
	if err != nil {
		var icErr intermediateCertsError
		if xerrors.As(err, &icErr) {
			return nil, InvalidIntermediateCertsFileError{err.Error()}
		}
		if isAuthFailError(err) {
			return nil, AuthFailError{tpm2.HandleOwner}
		}
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			if cpuid.HasFeature(cpuid.HYPERVISOR) {
				// Allow a fallback when running in a hypervisor in order to support swtpm
				return ConnectToDefaultTPM()
			}
			return nil, TPMVerificationError{fmt.Sprintf("cannot verify endorsement certificate: %s", err)}
		}
		return nil, xerrors.Errorf("cannot connect to TPM and verify endorsement certificate: %w", err)
	}

	return &TPMConnection{TPMContext: tpm, verifiedEkCertChain: chain}, nil
}

// SecureConnectToDefaultTPM will attempt to connect to the default TPM, verify the TPM's manufacturer issued endorsement certificate
// if it exists, and then verify that the TPM is the one for which the endorsement certificate was issued. The
// ekIntermediateCertsFile argument should point to a file created previously by FetchAndSaveEkIntermediateCerts. The endorsement
// certificate usually doesn't require an authorization value to obtain it from the TPM, but if the initial attempt to read it fails
// then this function will attempt to read it from the TPM using the storage hierarchy authorization as a fallback, which should be
// provided by ownerAuth.
//
// If the file referenced by ekIntermediateCertsFile cannot be loaded, a InvalidIntermediateCertsFileError error will be returned.
//
// If verification of the endorsement certificate fails or it doesn't exist at the expected location, a TPMVerificationError error
// will be returned.
//
// If the TPM doesn't contain an endorsement key at the expected location, ErrProvisioning will be returned.
//
// If the TPM cannot prove it is the device for which the endorsement certificate was issued, a TPMVerificationError error will be
// returned.
func SecureConnectToDefaultTPM(ekIntermediateCertsFile string, ownerAuth []byte) (*TPMConnection, error) {
	tpm, chain, err := connectToDefaultTPMAndVerifyEkCert(ekIntermediateCertsFile, ownerAuth)
	if err != nil {
		var icErr intermediateCertsError
		if xerrors.As(err, &icErr) {
			return nil, InvalidIntermediateCertsFileError{err.Error()}
		}
		if isAuthFailError(err) {
			return nil, AuthFailError{tpm2.HandleOwner}
		}
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			if cpuid.HasFeature(cpuid.HYPERVISOR) {
				// Allow a fallback when running in a hypervisor in order to support swtpm
				return ConnectToDefaultTPM()
			}
			return nil, TPMVerificationError{fmt.Sprintf("cannot verify endorsement certificate: %s", err)}
		}
		return nil, xerrors.Errorf("cannot connect to TPM and verify endorsement certificate: %w", err)
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.Close()
	}()

	t := &TPMConnection{TPMContext: tpm, verifiedEkCertChain: chain}

	if err := t.acquireEkContextAndVerifyTPM(); err != nil {
		var unavailErr tpm2.ResourceUnavailableError
		if xerrors.As(err, &unavailErr) {
			return nil, ErrProvisioning
		}
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return nil, TPMVerificationError{fmt.Sprintf("cannot verify TPM: %v", err)}
		}
		return nil, xerrors.Errorf("cannot acquire public area of the key associated with the TPM's endorsement certificate and verify "+
			"the TPM: %w", err)
	}

	succeeded = true
	return t, nil
}
