package main

import (
	"fmt"
	keys "tylerjgabb/tg-sb-auth/lib"
)

var rsaKeys *keys.Keys

func init() {
	rsaPrivateKeyLocation := "private_key.pem"
	rsaPublicKeyLocation := "public_key.pem"
	var err error
	rsaKeys, err = keys.LoadKeys(rsaPrivateKeyLocation, rsaPublicKeyLocation)
	if err != nil {
		panic(err)
	}
	fmt.Println("RSA keys loaded\n")
	fmt.Println("Public key JWK: ", string(rsaKeys.PublicKeyJwkJson))
	fmt.Println("My public key JWK: ", string(rsaKeys.MyPublicKeyJson))
}
