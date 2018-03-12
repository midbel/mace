package main

import (
	"bytes"
	"crypto"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
)

type Subject struct {
	Country      string `toml:"country"`
	State        string `toml:"state"`
	Locality     string `toml:"locality"`
	Organization string `toml:"organization"`
	Unit         string `toml:"unit"`
	Name         string `toml:"fqdn"`
	Email        string `toml:"email"`
}

func (s Subject) ToName() pkix.Name {
	value := func(s string) []string {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	return pkix.Name{
		Country:            value(s.Country),
		Province:           value(s.State),
		Locality:           value(s.Locality),
		Organization:       value(s.Organization),
		OrganizationalUnit: value(s.Unit),
		CommonName:         s.Name,
	}
}

type Certificate struct {
	Root   bool
	CACert string
	CAKey  string

	Period time.Duration
	Date   Time
	Hosts  StringArray
	Usages StringArray

	Curve string
	Bits  int
}

func (c Certificate) LoadCA() (*x509.Certificate, crypto.Signer, error) {
	return loadCA(c.CACert, c.CAKey)
}

func (c Certificate) Create(s Subject) (*x509.Certificate, crypto.Signer, error) {
	key, err := createPrivateKey(c.Curve, c.Bits)
	if err != nil {
		return nil, nil, err
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, nil, err
	}
	if c.Date.IsZero() {
		c.Date.Time = time.Now()
	}
	if c.Period == 0 {
		c.Period = time.Hour * 365 * 24
	}
	cert := x509.Certificate{
		Subject:               s.ToName(),
		SerialNumber:          serial,
		NotBefore:             c.Date.Time,
		NotAfter:              c.Date.Time.Add(c.Period),
		IsCA:                  c.Root,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if c.Root {
		cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if s.Email != "" {
		cert.EmailAddresses = []string{s.Email}
	}
	for _, h := range c.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}
	for _, u := range c.Usages {
		switch u {
		case "auth":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
		case "server":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		case "client":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case "any":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageAny)
		}
	}
	return &cert, key, nil
}

func runGenerate(cmd *cli.Command, args []string) error {
	var c Certificate

	name, err := os.Hostname()
	if err == nil {
		name = DefaultCertName
	}

	cmd.Flag.Var(&c.Hosts, "x", "hosts")
	cmd.Flag.Var(&c.Date, "t", "timestamp")
	cmd.Flag.Var(&c.Usages, "u", "usage")
	cmd.Flag.DurationVar(&c.Period, "d", 0, "days")
	cmd.Flag.StringVar(&c.CACert, "p", "", "ca certificate")
	cmd.Flag.StringVar(&c.CAKey, "k", "", "ca private key")
	cmd.Flag.StringVar(&c.Curve, "e", "", "elliptic curve")
	cmd.Flag.IntVar(&c.Bits, "c", DefaultRSAKeyLength, "")
	cmd.Flag.BoolVar(&c.Root, "r", false, "root ca")
	cmd.Flag.StringVar(&name, "n", name, "name")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var s Subject
	s.Country = prompt("Country Name (2 letter code): ")
	s.State = prompt("State Name (full name): ")
	s.Locality = prompt("Locality (eg, city): ")
	s.Organization = prompt("Organization (eg, company): ")
	s.Unit = prompt("Department (eg, IT): ")
	s.Name = prompt("Name (eg, server FQDN): ")
	s.Email = prompt("Email (eg, no-reply@foobar.com): ")

	cert, key, err := c.Create(s)
	if err != nil {
		return err
	}
	cacert, cakey, err := c.LoadCA()
	if err != nil {
		return err
	}
	if cacert == nil && cakey == nil {
		cacert, cakey = cert, key
	} else {
		cert.Issuer = cacert.Subject
	}

	bs, err := x509.CreateCertificate(rand.Reader, cert, cacert, key.Public(), cakey)
	if err != nil {
		return fmt.Errorf("create cert: %s", err)
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: BlockTypeCert, Bytes: bs}); err != nil {
		return fmt.Errorf("encode cert: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), name+".pem"), buf.Bytes(), 0400); err != nil {
		return err
	}
	return writePrivateKey(filepath.Join(cmd.Flag.Arg(0), name+".key"), key)
}
