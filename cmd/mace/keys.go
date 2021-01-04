package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/midbel/cli"
)

func runGenRSA(cmd *cli.Command, args []string) error {
	bits := cmd.Flag.Int("n", 2048, "bits")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	dir, name := filepath.Split(cmd.Flag.Arg(0))
	if err := os.MkdirAll(dir, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	if name == "" {
		name = "key.pem"
	}
	w, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	defer w.Close()
	priv, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		return err
	}
	bs := x509.MarshalPKCS1PrivateKey(priv)
	return pem.Encode(w, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bs})
}
