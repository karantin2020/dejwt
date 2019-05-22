package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	b64 "encoding/base64"

	cli "github.com/jawher/mow.cli"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Version of current app
const Version = "v0.1.0"

var (
	// ErrorWrongAlg describes unmarshal jwk error
	ErrorWrongAlg = errors.New("Not found jwk")
	// ErrUnmarshalAudience indicates that aud claim could not be unmarshalled.
	ErrUnmarshalAudience = errors.New("square/go-jose/jwt: expected string or array value to unmarshal to Audience")
)

// Claims holds jwt claims structure
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	ID        string   `json:"jti"`
}

func main() {
	app := cli.App("dejwt", "Cli tool to decode/encode jwt")

	app.Spec = "[-ea] -s [SRC]"
	app.Version("V version", Version)

	var (
		encode = app.BoolOpt("e encode", false, "Encode json string to signed jwt")
		secret = app.StringOpt("s secret", "", "Secret string to use (may be symmetric or asymmetric)")
		sigAlg = app.StringOpt("a alg", "", "Signature algorithm to sign. If not provided then "+
			"detect automatically. If it's impossible to auto detect alg then use HS256")
		src = app.StringArg("SRC", "", "Source string to encode/decode")
	)

	// Specify the action to execute when the app is invoked correctly
	app.Action = func() {
		if *secret == "" {
			fmt.Println("secret must not be empty string")
			cli.Exit(1)
		}
		if *src == "" {
			// fmt.Println("found empty src")
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				var stdin []byte
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					stdin = append(stdin, scanner.Bytes()...)
				}
				if err := scanner.Err(); err != nil {
					if err != nil {
						fmt.Println("error scanning input pipe:", err.Error())
					}
				}
				// fmt.Printf("stdin = %s\n", stdin)
				*src = string(stdin)
				*src = strings.Trim(*src, `"`)
			}
			if *src == "" {
				exitError()
			}
		}
		sDec, err := b64.StdEncoding.DecodeString(*secret)
		if err == nil {
			// fmt.Println("found base64 encoded secret")
			*secret = string(sDec)
		}
		sDec, err = b64.StdEncoding.DecodeString(*src)
		if err == nil {
			// fmt.Println("found base64 encoded src")
			*src = string(sDec)
		}
		// fmt.Println("found src: ", *src)
		if *encode == false {
			res, err := decodeJWT(*src, *secret)
			if err != nil {
				fmt.Printf("error decoding jwt: %s\n", err.Error())
				cli.Exit(1)
			}
			fmt.Println(res)
		} else {
			res, err := encodeJWT(*src, *secret, *sigAlg)
			if err != nil {
				fmt.Printf("error encoding jwt: %s\n", err.Error())
				cli.Exit(1)
			}
			fmt.Println(res)
		}

	}

	// Invoke the app passing in os.Args
	if err := app.Run(os.Args); err != nil {
		fmt.Printf("app exits with error: %s\n", err.Error())
		os.Exit(1)
	}
}

func encodeJWT(src, secret, sigAlg string) (string, error) {
	var alg jose.SignatureAlgorithm
	var key interface{} = []byte(secret)
	switch sigAlg {
	case "HS256":
		alg = jose.HS256
	case "HS384":
		alg = jose.HS384
	case "HS512":
		alg = jose.HS512
	default:
		jwk, err := unmarshalJWK(secret)
		if err != nil {
			alg = jose.HS256
			break
		}
		key = jwk
		alg = jose.SignatureAlgorithm(jwk.Algorithm)
	}
	// fmt.Printf("new signer with alg: '%s', key: %v\n", string(alg), key)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		fmt.Println("error create new signer:", err.Error())
		return "", err
	}
	srcMap := map[string]interface{}{}
	err = json.Unmarshal([]byte(src), &srcMap)
	if err != nil {
		fmt.Println("error unmarshal src:", err.Error())
		return "", err
	}
	// fmt.Printf("claims to sign: %v\n", srcMap)
	cl := Claims{Audience: []string{}}
	raw, err := jwt.Signed(sig).Claims(cl).Claims(srcMap).CompactSerialize()
	if err != nil {
		fmt.Println("error sign src:", err.Error())
		return "", err
	}
	return raw, nil
}

func decodeJWT(src, secret string) (string, error) {
	tok, err := jwt.ParseSigned(src)
	if err != nil {
		return "", errors.New("couldn't parse input src as correct jwt")
	}
	// fmt.Println("jwt was parsed well")
	var alg string
	for i := range tok.Headers {
		if tok.Headers[i].Algorithm != "" {
			alg = tok.Headers[i].Algorithm
			break
		}
	}
	if alg == "" {
		fmt.Println("invalid jwt with no alg header")
		cli.Exit(1)
	}
	// fmt.Println("found jwt alg:", alg)
	var sharedKey interface{}
	if alg == "HS256" || alg == "HS384" || alg == "HS512" {
		// fmt.Println("sharedKey is symmetric")
		sharedKey = []byte(secret)
	} else {
		sharedKey, err = unmarshalJWK(secret)
		if err != nil {
			fmt.Println("User provided secret is not correct JSONWebKey")
			cli.Exit(1)
		}
		// fmt.Printf("sharedKey is asymmetric: %#v\n", sharedKey)
	}
	// fmt.Printf("sharedKey is: %v\n", sharedKey)

	out := map[string]interface{}{}
	if err := tok.Claims(sharedKey, &out); err != nil {
		fmt.Println(err.Error())
		cli.Exit(1)
	}
	outJSON, err := json.Marshal(out)
	if err != nil {
		fmt.Println(err.Error())
		cli.Exit(1)
	}
	// fmt.Println(outJSON)
	return string(outJSON), nil
}

func unmarshalJWK(secret string) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}
	err := json.Unmarshal([]byte(secret), jwk)
	if err != nil {
		return nil, ErrorWrongAlg
	}
	return jwk, nil
}

func exitError() {
	fmt.Println("string to encode/decode must not be empty")
	cli.Exit(1)
}

// Audience represents the recipents that the token is intended for.
type Audience []string

// UnmarshalJSON reads an audience from its JSON representation.
func (s *Audience) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch v := v.(type) {
	case string:
		*s = []string{v}
	case []interface{}:
		a := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return ErrUnmarshalAudience
			}
			a[i] = s
		}
		*s = a
	default:
		return ErrUnmarshalAudience
	}

	return nil
}

// Contains checks for string include in list
func (s Audience) Contains(v string) bool {
	for _, a := range s {
		if a == v {
			return true
		}
	}
	return false
}
