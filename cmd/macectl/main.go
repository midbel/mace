package main

import (
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/midbel/cli"
)

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
		Usage: "generate [-t] [-e] [-d] [-p] [-k] [-c] [-r] [-n] [-x] <path>",
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
`,
	},
	{
		Usage: "genrsa [-n] <file>",
		Short: "generate a rsa key",
		Run:   runGenRSA,
	},
	{
		Usage: "verify",
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
