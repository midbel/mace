package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/midbel/cli"
)

func runVerify(cmd *cli.Command, args []string) error {
	root := cmd.Flag.String("r", "", "cert pool")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		pool *x509.CertPool
		err  error
	)
	if is, err := ioutil.ReadDir(*root); err == nil {
		pool = x509.NewCertPool()
		for _, i := range is {
			if i.IsDir() || filepath.Ext(i.Name()) == ".key" {
				continue
			}
			bs, err := ioutil.ReadFile(filepath.Join(*root, i.Name()))
			if err != nil {
				return fmt.Errorf("can not read %s: %s", i.Name(), err)
			}
			if ok := pool.AppendCertsFromPEM(bs); !ok {
				return fmt.Errorf("can not read certificate from %s: %s", i.Name(), err)
			}
		}
	} else {
		pool, err = x509.SystemCertPool()
	}
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{Roots: pool}
	for _, f := range cmd.Flag.Args() {
		bs, err := ioutil.ReadFile(f)
		if err != nil {
			return fmt.Errorf("can not read certificate %s: %s", f, err)
		}
		b, _ := pem.Decode(bs)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return fmt.Errorf("can not parse certificate %s: %s", f, err)
		}
		if _, err := c.Verify(opts); err != nil {
			log.Printf("invalid certificate %s: %s", f, err)
		}
	}
	return nil
}
