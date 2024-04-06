[![Version](https://img.shields.io/badge/goversion-1.20.x-blue.svg)](https://golang.org)
<a href="https://golang.org"><img src="https://img.shields.io/badge/powered_by-Go-3362c2.svg?style=flat-square" alt="Built with GoLang"></a>
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/tsawler/pasty/master/license.md)
[![Go Report Card](https://goreportcard.com/badge/github.com/tsawler/pasty)](https://goreportcard.com/report/github.com/tsawler/pasty)
![Tests](https://github.com/tsawler/pasty/actions/workflows/tests.yml/badge.svg)
<a href="https://pkg.go.dev/github.com/tsawler/pasty"><img src="https://img.shields.io/badge/godoc-reference-%23007d9c.svg"></a>
[![Go Coverage](https://github.com/tsawler/pasty/wiki/coverage.svg)](https://raw.githack.com/wiki/tsawler/pasty/coverage.html)


# Pasty

Pasty is a wrapper which makes working with PASETO tokens as simple as
possible. [PASETO](https://github.com/paragonie/paseto) (Platform-Agnostic SEcurity TOkens) is a specification for
secure stateless tokens.

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to hang themselves, PASETO only
allows secure operations. JWT gives you "algorithm agility", while PASETO gives you "versioned protocols." It's
unlikely that you'll be able to use PASETO insecurely.

This module uses [go-paseto](https://github.com/aidantwoods/go-paseto) to generate and validate tokens.

## PASETOs are NOT reusable tokens

PASETOs are **not** designed to be reusable tokens.

PASETOs should only be used once since they have no built-in mechanism for preventing replay attacks. If an attacker is
able to get a hold of a valid PASETO and can use it to make valid requests multiple times then you aren’t using PASETOs
correctly.

## Installation

Install it in the usual way:

```
go get -u github.com/tsawler/pasty
```

## Usage

To use this module, import it, and then generate a new `Pasty` type by calling the `New` function with the four
required parameters:

```go
// the four parameters are token type (public or local), issuer, audience, and identifier.
p, err := pasty.New("public", "issuer.com", "audience.com", "some-id")
if err != nil {
    log.Println(err)
    os.Exit(0)
}
```

When the above code runs, you have a variable named `p` of type `*pasty.Pasty`. With that variable, you can then 
generate and validate tokens:

```go
// add some additional claims to the token we're generating.
claims := make(map[string]any)
claims["user-id"] = 1
claims["subject"] = "10"

// generate the token, and add footer data if you want to.
t, err := p.GenerateToken(time.Now().Add(1*time.Hour), claims, "some footer data")
if err != nil {
    log.Println(err)
    os.Exit(0)
}

// validate the token:
valid, err := p.ValidatePublicToken(t)
if err != nil {
    log.Println(err)
}

// This will output: "token is valid: true"
fmt.Println("token is valid:", valid)
```

The full program:

```go
package main

import (
	"fmt"
	"github.com/tsawler/pasty"
	"log"
	"os"
	"time"
)

func main() {
	// the four parameters are token type (public or local), issuer, audience, and identifier.
	p, err := pasty.New("public", "issuer.com", "audience.com", "some-id")
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}

	// add some additional claims to the token we're generating.
	claims := make(map[string]any)
	claims["user-id"] = 1
	claims["subject"] = "10"

	// generate the token, and add footer data if you want to.
	t, err := p.GenerateToken(time.Now().Add(1*time.Hour), claims, "some footer data")
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}

	// validate the token:
	valid, err := p.ValidatePublicToken(t)
	if err != nil {
		log.Println(err)
	}

	// This will output: "token is valid: true"
	fmt.Println("token is valid:", valid)
}
```