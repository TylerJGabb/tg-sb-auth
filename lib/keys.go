package keys

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"os"

	"gopkg.in/square/go-jose.v2"
)

type parser func([]byte) (any, error)
type Keys struct {
	PrivateKey       *rsa.PrivateKey
	PublicKey        *rsa.PublicKey
	PublicKeyJwkJson []byte
	MyPublicKeyJson  []byte
}

type MyJwk struct {
	N       string `json:"n"`
	E       string `json:"e"`
	KeyId   string `json:"kid"`
	Alg     string `json:"alg"`
	KeyType string `json:"kty"`
	Use     string `json:"use"`
}

func parseKey(filePath string, parser parser) (any, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	pem, _ := pem.Decode(data)
	return parser(pem.Bytes)
}

func publicKeyJwkJson(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyJwk := jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     "key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	publicKeyJson, err := json.MarshalIndent(publicKeyJwk, "", "  ")
	if err != nil {
		return nil, err
	}
	return publicKeyJson, nil
}

func publicKeyJwkJsonMine(publicKey *rsa.PublicKey) ([]byte, error) {
	eData := make([]byte, 8)
	binary.BigEndian.PutUint64(eData, uint64(publicKey.E))
	publicKeyJwk := MyJwk{
		N:       base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:       base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(eData, "\x00")),
		KeyId:   "TODO--- key-id ---TODO",
		Alg:     "RS256",
		KeyType: "RSA",
		Use:     "sig",
	}

	publicKeyJson, err := json.MarshalIndent(publicKeyJwk, "", "  ")
	if err != nil {
		return nil, err
	}
	return publicKeyJson, nil
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
	publicKeyJwkJson, err := publicKeyJwkJson(publicKey.(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}
	myPublicKeyJwkJson, err := publicKeyJwkJsonMine(publicKey.(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}

	return &Keys{
		PrivateKey:       privateKey.(*rsa.PrivateKey),
		PublicKey:        publicKey.(*rsa.PublicKey),
		PublicKeyJwkJson: publicKeyJwkJson,
		MyPublicKeyJson:  myPublicKeyJwkJson,
	}, nil
}
