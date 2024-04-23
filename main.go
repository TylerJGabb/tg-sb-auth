package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

func main() {
	// https://gist.github.com/nilsmagnus/199d56ce849b83bdd7df165b25cb2f56
	rsaPrivateKeyLocation := "private_key.pem"
	rsaPublicKeyLocation := "public_key.pem"
	priv, err := os.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		panic(err)
	}
	privPem, _ := pem.Decode(priv)
	var parsedKey any
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
			panic("Failed to parse PKCS8 private key: " + err.Error())
		}
	}
	privateKey := parsedKey.(*rsa.PrivateKey)

	pub, err := os.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		panic(err)
	}
	pubPem, _ := pem.Decode(pub)
	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		panic(err)
	}
	publicKey := parsedKey.(*rsa.PublicKey)
	privateKey.PublicKey = *publicKey

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   "principal-the-token-is-issued-for",
		Issuer:    "tg-sb.com",
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 2).UTC().Unix(),
	})
	tokenString, err := newToken.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(tokenString)

	// Verify token signature
	parsedToken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		panic(err)
	} else if parsedToken.Valid {
		fmt.Println("Token signature is valid")
	} else {
		panic("Token signature is invalid")
	}

}
