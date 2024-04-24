package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose"
	"github.com/golang-jwt/jwt"
)

func main() {
	fmt.Println("for /.well-known/jwks.json: ", string(rsaKeys.WellKnownJwks))
	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   "principal-the-token-is-issued-for",
		Issuer:    "tg-sb.com",
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 2).UTC().Unix(),
		Audience:  "the-recepients-the-token-is-intended-for",
	})
	tokenString, err := newToken.SignedString(rsaKeys.PrivateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(tokenString)

	// pretend you're a client wanting to validate, and you request /.well-known/jwks.json
	jwksFromApi := rsaKeys.WellKnownJwks
	jwkKeys := jose.JSONWebKeySet{}
	if err := json.Unmarshal(jwksFromApi, &jwkKeys); err != nil {
		panic(err)
	}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if len(jwkKeys.Keys) == 0 {
			return nil, fmt.Errorf("no keys found in jwks")
		}
		return jwkKeys.Keys[0].Key, nil
	}

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
