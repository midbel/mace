package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

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
	certfile := cmd.Flag.String("p", "", "ca certificate")
	keyfile := cmd.Flag.String("k", "", "ca private key")
	certdir := cmd.Flag.String("d", "", "certificate directory")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*certdir, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	cacert, cakey, err := loadCA(*certfile, *keyfile)
	if err != nil {
		return err
	}
	for _, a := range cmd.Flag.Args() {
		bs, err := ioutil.ReadFile(a)
		if err != nil {
			log.Printf("fail to read %s: %s", a, err)
			continue
		}
		b, _ := pem.Decode(bs)
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil {
			log.Printf("fail to parse CSR from %s: %s", a, err)
		}
		if err := csr.CheckSignature(); err != nil {
			log.Printf("fail to validate signature of %s: %s", a, err)
		}
		limit := new(big.Int).Lsh(big.NewInt(1), 128)
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return err
		}
		now := time.Now()
		cert := x509.Certificate{
			Subject:               csr.Subject,
			SerialNumber:          serial,
			NotBefore:             now,
			NotAfter:              now.Add(time.Hour * 24 * 365),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IPAddresses:           csr.IPAddresses,
			DNSNames:              csr.DNSNames,
			EmailAddresses:        csr.EmailAddresses,
		}
		bs, err = x509.CreateCertificate(rand.Reader, &cert, cacert, csr.PublicKey, cakey)
		if err != nil {
			log.Printf("fail to create certificate from %s: %s", a, err)
			continue
		}
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: BlockTypeCert, Bytes: bs}); err != nil {
			log.Println("fail to encode certificate from %s: %s", a, err)
			continue
		}
		name := filepath.Base(a) + ".crt"
		if err := ioutil.WriteFile(filepath.Join(*certdir, name), buf.Bytes(), 0400); err != nil {
			log.Println("fail to write certificate from %s: %s")
		}
	}
	return nil
}

func runConvertToCSR(cmd *cli.Command, args []string) error {
	certdir := cmd.Flag.String("d", "", "certificates directory")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*certdir, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	for _, a := range cmd.Flag.Args() {
		bs, err := ioutil.ReadFile(a)
		if err != nil {
			continue
		}
		b, _ := pem.Decode(bs)
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		csr := x509.CertificateRequest{
			Subject:        cert.Subject,
			IPAddresses:    cert.IPAddresses,
			DNSNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}
		bs, err = x509.CreateCertificateRequest(rand.Reader, &csr, nil)
		if err != nil {
			continue
		}
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: BlockTypeCSR, Bytes: bs}); err != nil {
			continue
		}
		name := filepath.Base(a)
		if err := ioutil.WriteFile(filepath.Join(*certdir, name+".csr"), buf.Bytes(), 0400); err != nil {
			continue
		}
	}
	return nil
}
