package main

import (
	"fmt"
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

const helpText = `{{.Name}} contains various actions to monitor system activities.

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
		Short: "generate certificates",
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
		Usage: "sign",
		Short: "sign a CSR from a ca certificate",
		Run:   runSignCSR,
	},
	{
		Usage: "emit [-e] [-c] [-n] [-x] <path>",
		Short: "create a new certificate request",
		Run:   runEmitCSR,
	},
	{
		Usage: "revoke <cert>",
		Short: "revoke a certificate",
	},
	{
		Usage: "verify [-r] [-i] <cert...>",
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
