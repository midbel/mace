package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/midbel/cli"
)

type Request struct {
	Hosts StringArray

	Curve string
	Bits  int
}

func (r Request) Create(s Subject) (*x509.CertificateRequest, crypto.Signer, error) {
	key, err := createPrivateKey(r.Curve, r.Bits)
	if err != nil {
		return nil, nil, err
	}
	cert := x509.CertificateRequest{
		Subject: s.ToName(),
	}
	if s.Email != "" {
		cert.EmailAddresses = []string{s.Email}
	}
	for _, h := range r.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}
	return &cert, key, nil
}

func runEmitCSR(cmd *cli.Command, args []string) error {
	var r Request

	name, err := os.Hostname()
	if err == nil {
		name = "localhost"
	}

	cmd.Flag.Var(&r.Hosts, "x", "")
	cmd.Flag.IntVar(&r.Bits, "c", DefaultRSAKeyLength, "")
	cmd.Flag.StringVar(&r.Curve, "e", "", "")
	cmd.Flag.StringVar(&name, "n", name, "")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	prompt := func(label string, v interface{}) {
		fmt.Print(label)
		fmt.Scanln(v)
	}

	var s Subject
	prompt("Country Name (2 letter code): ", &s.Country)
	prompt("State Name (full name): ", &s.State)
	prompt("Locality (eg, city): ", &s.Locality)
	prompt("Organization (eg, company): ", &s.Organization)
	prompt("Department (eg, IT): ", &s.Unit)
	prompt("Name (eg, server FQDN): ", &s.Name)
	prompt("Email (eg, no-reply@foobar.com): ", &s.Email)

	csr, key, err := r.Create(s)
	if err != nil {
		return err
	}

	bs, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		return fmt.Errorf("create csr: %s", err)
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: BlockTypeCSR, Bytes: bs}); err != nil {
		return fmt.Errorf("encode csr: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), name+".pem"), buf.Bytes(), 0400); err != nil {
		return err
	}
	return writePrivateKey(filepath.Join(cmd.Flag.Arg(0), name+".key"), key)
}

func runSignCSR(cmd *cli.Command, args []string) error {
	return cmd.Flag.Parse(args)
}

func runConvertToCSR(cmd *cli.Command, args []string) error {
	return cmd.Flag.Parse(args)
}
