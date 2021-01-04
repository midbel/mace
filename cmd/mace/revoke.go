package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
)

func runRevoke(cmd *cli.Command, args []string) error {
	var (
		cert    Certificate
		key     PrivateKey
		expired Time
		datadir string
	)
	cmd.Flag.Var(&cert, "c", "certificate")
	cmd.Flag.Var(&key, "k", "private key")
	cmd.Flag.Var(&expired, "e", "expired")
	cmd.Flag.StringVar(&datadir, "d", "", "datadir")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	n := time.Now().Truncate(time.Hour * 24)
	if expired.IsZero() {
		expired.Time = n
	}
	if k := cert.Cert.KeyUsage & x509.KeyUsageCRLSign; k != x509.KeyUsageCRLSign {
		return x509.CertificateInvalidError{
			Cert:   cert.Cert,
			Reason: x509.IncompatibleUsage,
			Detail: "can not sign CRL",
		}
	}

	var rs []pkix.RevokedCertificate
	for _, a := range cmd.Flag.Args() {
		c, err := readCertificate(a)
		if err != nil {
			return err
		}
		k := pkix.RevokedCertificate{
			SerialNumber:   c.SerialNumber,
			RevocationTime: n,
		}
		rs = append(rs, k)
	}
	bs, err := cert.Cert.CreateCRL(rand.Reader, key.Key, rs, n, expired.Time)
	if err != nil {
		return err
	}
	file := filepath.Join(*datadir, "crl.pem")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: BlockTypeCRL, Bytes: bs})
}
