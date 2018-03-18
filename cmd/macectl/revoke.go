package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"time"

	"github.com/midbel/cli"
)

func runRevoke(cmd *cli.Command, args []string) error {
	var (
		cert cli.Certificate
		key  cli.PrivateKey
	)
	cmd.Flag.Var(&cert, "c", "certificate")
	cmd.Flag.Var(&key, "k", "private key")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	n := time.Now()

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
	bs, err := cert.Cert.CreateCRL(rand.Reader, key.Key, rs, n, n)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(cmd.Flag.Arg(0), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: "CRL", Bytes: bs})
}
