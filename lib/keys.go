package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"

	"github.com/go-jose/go-jose/v4"
)

type parser func([]byte) (any, error)
type Keys struct {
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
	WellKnownJwks []byte
}

func parseKey(filePath string, parser parser) (any, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	pem, _ := pem.Decode(data)
	return parser(pem.Bytes)
}

func wellKnownJwksJson(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyJwk := jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     "key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	jwkSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKeyJwk}}
	jwkSetJson, err := json.MarshalIndent(jwkSet, "", "  ")
	if err != nil {
		return nil, err
	}
	return jwkSetJson, nil
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
	publicKeyJwkJson, err := wellKnownJwksJson(publicKey.(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}

	return &Keys{
		PrivateKey:    privateKey.(*rsa.PrivateKey),
		PublicKey:     publicKey.(*rsa.PublicKey),
		WellKnownJwks: publicKeyJwkJson,
	}, nil
}
