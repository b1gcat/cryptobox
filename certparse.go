package main

import (
	"encoding/pem"
	"regexp"
	"strings"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"
)

func parseCert(x []byte) (*smx509.Certificate, error) {
	if strings.HasPrefix(string(x), "----") {
		return smx509.ParseCertificatePEM(x)
	} else {
		return smx509.ParseCertificate(x)
	}

}

func parseChain(chainType string, chain []byte) ([]*smx509.Certificate, error) {
	if chainType == "p7b" {
		var p7Bytes []byte

		p7Bytes = chain
		if strings.HasPrefix(string(chain), "----") {
			//不支持多个pem块
			p, _ := pem.Decode(chain)
			p7Bytes = p.Bytes
		}

		p7, err := pkcs7.Parse(p7Bytes)
		if err != nil {
			return nil, err
		}
		return p7.Certificates, nil
	}

	c := make([]*smx509.Certificate, 0)
	var re = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----`)

	for _, match := range re.FindAllString(string(chain), -1) {
		x, err := smx509.ParseCertificatePEM([]byte(match))
		if err != nil {
			return nil, err
		}
		c = append(c, x)
	}
	return c, nil
}
