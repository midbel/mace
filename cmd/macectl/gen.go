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
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/midbel/cli"
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
	Name string

	Root   bool
	CACert string
	CAKey  string

	Period time.Duration
	Date   Time
	Hosts  StringArray

	Curve string
	Bits  int
}

func (c Certificate) LoadCA() (*x509.Certificate, *rsa.PrivateKey, error) {
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
	if bs, err = ioutil.ReadFile(c.CAKey); err != nil {
		return nil, nil, err
	}
	b, _ = pem.Decode(bs)
	key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (c Certificate) Create(s Subject) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, c.Bits)
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
		cert.KeyUsage |= x509.KeyUsageCertSign
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
	cmd.Flag.IntVar(&c.Bits, "c", 2048, "")
	cmd.Flag.BoolVar(&c.Root, "r", false, "root ca")
	cmd.Flag.StringVar(&c.Name, "n", name, "name")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	sub := readSubject()
	cert, key, err := c.Create(sub)
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
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs}); err != nil {
		return fmt.Errorf("encode cert: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), c.Name+".pem"), buf.Bytes(), 0600); err != nil {
		return err
	}
	buf.Reset()

	bs = x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bs}); err != nil {
		return fmt.Errorf("encode rsa key: %s", err)
	}
	return ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), c.Name+".key"), buf.Bytes(), 0600)
}

func readSubject() Subject {
	var s Subject

	fmt.Print("Country Name (2 letter code) []: ")
	fmt.Scanln(&s.Country)
	fmt.Print("State Name (full name) []: ")
	fmt.Scanln(&s.State)
	fmt.Print("Locality (eg, city) []: ")
	fmt.Scanln(&s.Locality)
	fmt.Print("Organization (eg, company) []: ")
	fmt.Scanln(&s.Organization)
	fmt.Printf("Department (eg, IT) [%s]: ", s.Unit)
	fmt.Scanln(&s.Unit)
	fmt.Printf("Name (eg, server FQDN) [%s]: ", s.Name)
	fmt.Scanln(&s.Name)
	fmt.Printf("Email (eg, no-reply@foobar.com) []: ")
	fmt.Scanln(&s.Email)

	return s
}
