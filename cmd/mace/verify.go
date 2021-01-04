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
	rootdir := cmd.Flag.String("r", "", "root ca certificates")
	intdir := cmd.Flag.String("i", "", "intermediate ca certificates")
	host := cmd.Flag.String("x", "", "host")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	base, err := Pool(*rootdir, true)
	if err != nil {
		return err
	}
	other, _ := Pool(*intdir, false)

	opts := x509.VerifyOptions{
		Roots:         base,
		Intermediates: other,
		DNSName:       *host,
	}
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
			continue
		}
		log.Printf("%s: OK", f)
	}
	return nil
}

func Pool(dir string, sys bool) (*x509.CertPool, error) {
	is, err := ioutil.ReadDir(dir)
	if err != nil && sys {
		return x509.SystemCertPool()
	}
	pool := x509.NewCertPool()
	for _, i := range is {
		if i.IsDir() || filepath.Ext(i.Name()) == ".key" {
			continue
		}
		bs, err := ioutil.ReadFile(filepath.Join(dir, i.Name()))
		if err != nil {
			return nil, fmt.Errorf("can not read %s: %s", i.Name(), err)
		}
		if ok := pool.AppendCertsFromPEM(bs); !ok {
			return nil, fmt.Errorf("can not read certificate from %s: %s", i.Name(), err)
		}
	}
	return pool, nil
}
