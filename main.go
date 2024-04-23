package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

func main() {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaKeys.PublicKey, nil
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   "principal-the-token-is-issued-for",
		Issuer:    "tg-sb.com",
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 2).UTC().Unix(),
	})
	tokenString, err := newToken.SignedString(rsaKeys.PrivateKey)
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
