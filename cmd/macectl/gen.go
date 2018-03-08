package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
)

func runGenerate(cmd *cli.Command, args []string) error {
	stamp := cmd.Flag.String("t", "", "timestamp")
	days := cmd.Flag.Duration("d", 0, "days")
	parent := cmd.Flag.String("p", "", "")
	bits := cmd.Flag.Int("c", 2048, "")
	orga := cmd.Flag.String("o", "", "organization")
	root := cmd.Flag.Bool("r", false, "root ca")
	name := cmd.Flag.String("n", "mace", "name")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	now := time.Now()
	if n, err := time.Parse(time.RFC3339, *stamp); err == nil {
		now = n
	}
	if *days <= 0 {
		*days = time.Hour * 24 * 365
	}

	priv, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		return err
	}

	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{*orga}},
		NotBefore:             now,
		NotAfter:              now.Add(*days),
		IsCA:                  *root,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if *root {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	other := template
	if bs, err := ioutil.ReadFile(*parent); err == nil {
		b, _ := pem.Decode(bs)
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			other = *c
		}
	}
	bs, err := x509.CreateCertificate(rand.Reader, &template, &other, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %s", err)
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs}); err != nil {
		return fmt.Errorf("encode cert: %s", err)
	}
	if err := os.MkdirAll(cmd.Flag.Arg(0), 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), *name+".cert"), buf.Bytes(), 0600); err != nil {
		return err
	}
	buf.Reset()

	bs = x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bs}); err != nil {
		return fmt.Errorf("encode key: %s", err)
	}
	return ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), *name+".key"), buf.Bytes(), 0600)
}
