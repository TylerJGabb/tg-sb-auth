package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

type parser func([]byte) (any, error)
type Keys struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func parseKey(filePath string, parser parser) (any, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	pem, _ := pem.Decode(data)
	return parser(pem.Bytes)
}

func LoadKeys(
	privateKeyPath string,
	publicKeyPath string,
) (*Keys, error) {
	privateKey, err := parseKey(privateKeyPath, x509.ParsePKCS8PrivateKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := parseKey(publicKeyPath, x509.ParsePKIXPublicKey)
	if err != nil {
		return nil, err
	}
	return &Keys{
		PrivateKey: privateKey.(*rsa.PrivateKey),
		PublicKey:  publicKey.(*rsa.PublicKey),
	}, nil
}
