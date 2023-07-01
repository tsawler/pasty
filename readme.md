# Pasty

Pasty is a wrapper which makes working with Paseto tokens as simple as
possible. [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic SEcurity TOkens) is a specification for
secure stateless tokens.

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to hang themselves, Paseto only
allows secure operations. JWT gives you "algorithm agility", while Paseto gives you "versioned protocols." It's
unlikely that you'll be able to use Paseto insecurely.

This module uses [go-paseto](https://github.com/aidantwoods/go-paseto) to generate and validate tokens.

## Pasetos are NOT reusable tokens

Pasetos are **not** designed to be reusable tokens.

Pasetos should only be used once since they have no built-in mechanism for preventing replay attacks. If an attacker is
able to get a hold of a valid Paseto and can use it to make valid requests multiple times then you aren’t using Pasetos
correctly.

## Installation

Install it in the usual way:

```
go get -u github.com/tsawler/pasty
```

## Usage

To use this module, import it, and then generate a new Pasty type by calling the `New` function with the four
required parameters:

```go
// the four parameters are token type (public or local), issuer, audience, and identifier.
p, err := pasty.New("public", "example.com", "example.com", "example.com")
if err != nil {
    log.Println(err)
    os.Exit(0)
}
```