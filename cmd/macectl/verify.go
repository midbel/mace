package main

import (
	"github.com/midbel/cli"
)

func runVerify(cmd *cli.Command, args []string) error {
	return cmd.Flag.Parse(args)
}
