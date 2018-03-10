package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/midbel/cli"
)

const (
	BlockTypeRSA   = "RSA PRIVATE KEY"
	BlockTypeECDSA = "EC PRIVATE KEY"
	BlockTypeCert  = "CERTIFICATE"
)

type Time struct {
	time.Time
}

func (t *Time) String() string {
	return t.Time.String()
}

func (t *Time) Set(v string) error {
	i, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return err
	}
	t.Time = i
	return nil
}

type StringArray []string

func (s *StringArray) String() string {
	return fmt.Sprint(*s)
}

func (s *StringArray) Set(vs string) error {
	for _, v := range strings.Split(vs, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		*s = append(*s, v)
	}
	return nil
}

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

	Curve string
	Bits  int
}

func (c Certificate) LoadCA() (*x509.Certificate, crypto.Signer, error) {
	var (
		b   *pem.Block
		bs  []byte
		err error
	)
	switch bs, err = ioutil.ReadFile(c.CACert); {
	case err == nil:
	case os.IsNotExist(err):
		return nil, nil, nil
	default:
		return nil, nil, err
	}
	b, _ = pem.Decode(bs)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("not a ca certificate")
	}
	if bs, err = ioutil.ReadFile(c.CAKey); err != nil {
		return nil, nil, err
	}
	b, _ = pem.Decode(bs)

	var key crypto.Signer
	switch b.Type {
	case BlockTypeRSA:
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case BlockTypeECDSA:
		key, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return nil, nil, fmt.Errorf("unrecognized block type for CA key %s", b.Type)
	}
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (c Certificate) Create(s Subject) (*x509.Certificate, crypto.Signer, error) {
	var (
		key crypto.Signer
		err error
	)
	switch c.Curve {
	case "":
		key, err = rsa.GenerateKey(rand.Reader, c.Bits)
	case "P224":
		key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unrecognized curve %s", c.Curve)
	}
	if err != nil {
		return nil, nil, err
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, nil, err
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
	return &cert, key, nil
}

func runGenerate(cmd *cli.Command, args []string) error {
	var c Certificate

	name, err := os.Hostname()
	if err == nil {
		name = "localhost"
	}

	cmd.Flag.Var(&c.Hosts, "x", "hosts")
	cmd.Flag.Var(&c.Date, "t", "timestamp")
	cmd.Flag.DurationVar(&c.Period, "d", 0, "days")
	cmd.Flag.StringVar(&c.CACert, "p", "", "ca certificate")
	cmd.Flag.StringVar(&c.CAKey, "k", "", "ca private key")
	cmd.Flag.StringVar(&c.Curve, "e", "", "elliptic curve")
	cmd.Flag.IntVar(&c.Bits, "c", 2048, "")
	cmd.Flag.BoolVar(&c.Root, "r", false, "root ca")
	cmd.Flag.StringVar(&name, "n", name, "name")
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

func writePrivateKey(p string, s crypto.Signer) error {
	var (
		bs []byte
		t  string
	)
	switch k := s.(type) {
	case *rsa.PrivateKey:
		bs = x509.MarshalPKCS1PrivateKey(k)
		t = BlockTypeRSA
	case *ecdsa.PrivateKey:
		vs, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		bs, t = vs, BlockTypeECDSA
	default:
		return fmt.Errorf("unrecognized private key type  (%T)", s)
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: t, Bytes: bs}); err != nil {
		return fmt.Errorf("encode key: %s", err)
	}
	return ioutil.WriteFile(p, buf.Bytes(), 0400)
}
