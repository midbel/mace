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
	"os"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/midbel/cli"
	"github.com/midbel/toml"
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
	return pkix.Name{
		Country:            []string{s.Country},
		Province:           []string{s.State},
		Locality:           []string{s.Locality},
		Organization:       []string{s.Organization},
		OrganizationalUnit: []string{s.Unit},
		CommonName:         s.Name,
	}
}

func runGenerate(cmd *cli.Command, args []string) error {
	var hs hosts
	cmd.Flag.Var(&hs, "x", "hosts")
	stamp := cmd.Flag.String("t", "", "timestamp")
	days := cmd.Flag.Duration("d", 0, "days")
	parent := cmd.Flag.String("p", "", "")
	setting := cmd.Flag.String("s", "", "subject")
	bits := cmd.Flag.Int("c", 2048, "")
	root := cmd.Flag.Bool("r", false, "root ca")
	curve := cmd.Flag.String("e", "", "ecdsa")
	name := cmd.Flag.String("n", "mace", "name")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(cmd.Flag.Arg(0), 0700); err != nil && !os.IsExist(err) {
		return err
	}

	now := time.Now().Truncate(time.Minute * 5)
	if n, err := time.Parse(time.RFC3339, *stamp); err == nil {
		now = n
	}
	if *days <= 0 {
		*days = time.Hour * 24 * 365
	}
	var (
		priv interface{}
		err  error
	)
	switch strings.ToLower(*curve) {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, *bits)
	case "p256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return fmt.Errorf("unrecognized curve %s", *curve)
	}
	if err != nil {
		return err
	}

	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return fmt.Errorf("fail to generate serial number: %s", err)
	}

	sub := readSubject(*setting)
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               sub.ToName(),
		NotBefore:             now,
		NotAfter:              now.Add(*days),
		IsCA:                  *root,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if sub.Email != "" {
		template.EmailAddresses = []string{sub.Email}
	}
	if *root {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	other := template
	if bs, err := ioutil.ReadFile(*parent); err == nil {
		b, _ := pem.Decode(bs)
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			other = *c
			if other.IsCA {
				template.Issuer = other.Issuer
			}
		} else {
			return err
		}
	}
	for _, h := range hs {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	bs, err := x509.CreateCertificate(rand.Reader, &template, &other, publicKey(priv), priv)
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

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		bs := x509.MarshalPKCS1PrivateKey(k)
		if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bs}); err != nil {
			return fmt.Errorf("encode rsa key: %s", err)
		}
	case *ecdsa.PrivateKey:
		bs, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return fmt.Errorf("encode ecdsa key: %s", err)
		}
		if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bs}); err != nil {
			return fmt.Errorf("encode ecdsa key: %s", err)
		}
	}
	return ioutil.WriteFile(filepath.Join(cmd.Flag.Arg(0), *name+".key"), buf.Bytes(), 0600)
}

func publicKey(p interface{}) crypto.PublicKey {
	switch k := p.(type) {
	case *rsa.PrivateKey:
		return k.Public()
	case *ecdsa.PrivateKey:
		return k.Public()
	}
	return nil
}

func readSubject(f string) subject {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "localhost"
	}
	s := subject{
		Unit: h,
		Name: h,
	}
	if f, err := os.Open(f); err == nil {
		defer f.Close()
		if err := toml.NewDecoder(f).Decode(&s); err == nil {
			return s
		}
	}
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
