package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/midbel/cli"
)

const (
	DefaultRSAKeyLength = 2048
	DefaultCertName     = "localhost"
)

const (
	BlockTypeRSA   = "RSA PRIVATE KEY"
	BlockTypeECDSA = "EC PRIVATE KEY"
	BlockTypeCert  = "CERTIFICATE"
	BlockTypeCSR   = "CERTIFICATE REQUEST"
)

type Time struct {
	time.Time
}

func (t *Time) String() string {
	return t.Time.String()
}

func (t *Time) Set(v string) error {
	if v == "" {
		t.Time = time.Now()
		return nil
	}
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

const helpText = `{{.Name}} help you to manage easily your X509 certificates.

Usage:

  {{.Name}} command [arguments]

The commands are:

{{range .Commands}}{{printf "  %-9s %s" .String .Short}}
{{end}}

Use {{.Name}} [command] -h for more information about its usage.
`

var commands = []*cli.Command{
	{
		Usage: "generate [-t] [-e] [-d] [-p] [-k] [-c] [-r] [-n] [-x] [-u] <path>",
		Alias: []string{"gen"},
		Short: "generate certificate",
		Run:   runGenerate,
		Desc: `

options:
  -t date
  -d period
  -p parent
  -c bits
  -r root
  -n name
  -x host
  -e curve
	-u usage
`,
	},
	{
		Usage: "genrsa [-n] <file>",
		Short: "generate a rsa key",
		Run:   runGenRSA,
	},
	{
		Usage: "sign [-d] [-p] [-k] <certificate,...>",
		Short: "sign a CSR from a CA certificate",
		Run:   runSignCSR,
	},
	{
		Usage: "emit [-e] [-c] [-n] [-x] <path>",
		Short: "create a new certificate signing request",
		Run:   runEmitCSR,
	},
	{
		Usage: "convert [-d] [-k] <certificate,...>",
		Short: "emit a new certificate signing request from an existing certificate",
		Run:   runConvertToCSR,
	},
	{
		Usage: "revoke <cert>",
		Short: "revoke a certificate",
		Run:   runRevoke,
	},
	{
		Usage: "verify [-r] [-i] <certificate,...>",
		Alias: []string{"check"},
		Short: "verify certificates",
		Run:   runVerify,
	},
}

func main() {
	log.SetFlags(0)
	usage := func() {
		data := struct {
			Name     string
			Commands []*cli.Command
		}{
			Name:     filepath.Base(os.Args[0]),
			Commands: commands,
		}
		t := template.Must(template.New("help").Parse(helpText))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, nil); err != nil {
		log.Fatalln(err)
	}
}

func prompt(s string) string {
	fmt.Print(s)
	r := bufio.NewReader(os.Stdin)
	v, _ := r.ReadString('\n')
	return strings.TrimSpace(v)
}

func loadCA(cacert, cakey string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := readCertificate(cacert)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return nil, nil, nil
	default:
		return nil, nil, err
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("not a ca certificate")
	}
	key, err := readPrivateKey(cakey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func readCertificate(file string) (*x509.Certificate, error) {
	bs, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(bs)
	if b.Type != BlockTypeCert {
		return nil, fmt.Errorf("unexpected block type %s", b.Type)
	}
	return x509.ParseCertificate(b.Bytes)
}

func readPrivateKey(file string) (crypto.Signer, error) {
	bs, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(bs)

	var key crypto.Signer
	switch b.Type {
	case BlockTypeRSA:
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case BlockTypeECDSA:
		key, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %s", b.Type)
	}
	return key, err
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

func createPrivateKey(c string, n int) (crypto.Signer, error) {
	var (
		key crypto.Signer
		err error
	)
	switch c {
	case "":
		key, err = rsa.GenerateKey(rand.Reader, n)
	case "P224":
		key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("unrecognized curve %s", c)
	}
	return key, err
}
