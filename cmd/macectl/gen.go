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
	"path/filepath"
	"strings"
	"time"

	"github.com/midbel/cli"
)

type hosts []string

func (h *hosts) String() string {
	return fmt.Sprint(*h)
}

func (h *hosts) Set(vs string) error {
	for _, v := range strings.Split(vs, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		*h = append(*h, v)
	}
	if len(*h) == 0 {
		return fmt.Errorf("no hosts provided")
	}
	return nil
}

type subject struct {
	Country      string `toml:"country"`
	State        string `toml:"state"`
	Locality     string `toml:"locality"`
	Organization string `toml:"organization"`
	Unit         string `toml:"unit"`
	Name         string `toml:"fqdn"`
	Email        string `toml:"email"`
}

func (s subject) ToName() pkix.Name {
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

func runGenerate(cmd *cli.Command, args []string) error {
	var hs hosts
	cmd.Flag.Var(&hs, "x", "hosts")
	stamp := cmd.Flag.String("t", "", "timestamp")
	days := cmd.Flag.Duration("d", 0, "days")
	parent := cmd.Flag.String("p", "", "")
	sign := cmd.Flag.String("k", "", "")
	bits := cmd.Flag.Int("c", 2048, "")
	root := cmd.Flag.Bool("r", false, "root ca")
	name := cmd.Flag.String("n", "mace", "name")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	sub := readSubject()

	t, err := createCertificate(*stamp, *days, *root)
	if err != nil {
		return err
	}
	t.Subject = sub.ToName()
	if sub.Email != "" {
		t.EmailAddresses = []string{sub.Email}
	}
	for _, h := range hs {
		if ip := net.ParseIP(h); ip != nil {
			t.IPAddresses = append(t.IPAddresses, ip)
		} else {
			t.DNSNames = append(t.DNSNames, h)
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		return err
	}

	other := t

	pkey := priv
	if bs, err := ioutil.ReadFile(*parent); err == nil {
		b, _ := pem.Decode(bs)
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			other = c
			if other.IsCA {
				t.Issuer = other.Issuer
			}
		} else {
			return err
		}
		if bs, err := ioutil.ReadFile(*sign); err == nil {
			b, _ := pem.Decode(bs)
			pkey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return fmt.Errorf("parse signer key: %s", err)
			}
		} else {
			return err
		}
	}

	bs, err := x509.CreateCertificate(rand.Reader, t, other, priv.Public(), pkey)
	if err != nil {
		return fmt.Errorf("create cert: %s", err)
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs}); err != nil {
		return fmt.Errorf("encode cert: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), *name+".pem"), buf.Bytes(), 0600); err != nil {
		return err
	}
	buf.Reset()

	bs = x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bs}); err != nil {
		return fmt.Errorf("encode rsa key: %s", err)
	}
	return ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), *name+".key"), buf.Bytes(), 0600)
}

func createCertificate(s string, d time.Duration, ca bool) (*x509.Certificate, error) {
	now := time.Now().Truncate(time.Minute * 5)
	if n, err := time.Parse(time.RFC3339, s); err == nil {
		now = n
	} else {
		return nil, err
	}
	if d <= 0 {
		d = time.Hour * 24 * 365
	}

	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("fail to generate serial number: %s", err)
	}

	t := x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now,
		NotAfter:              now.Add(d),
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	if ca {
		t.KeyUsage |= x509.KeyUsageCertSign
	}
	return &t, nil
}

func readSubject() subject {
	var s subject

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
