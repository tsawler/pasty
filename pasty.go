package pasty

import (
	"aidanwoods.dev/go-paseto"
	"errors"
	"log"
	"strings"
	"time"
)

type Pasty struct {
	Key       paseto.V4SymmetricKey
	Purpose   string
	Expiry    time.Time
	PublicKey paseto.V4AsymmetricPublicKey
	SecretKey paseto.V4AsymmetricSecretKey
	LocalKey  paseto.V4SymmetricKey
	Issuer    string
}

func New(expires time.Time, tokenPurpose ...string) (*Pasty, error) {
	// Set the default purpose to public. If the variadic parameter tokenPurpose
	// is set, we'll use that instead.
	purpose := "public"

	secretKey := paseto.NewV4AsymmetricSecretKey()
	localKey := paseto.NewV4SymmetricKey()
	publicKey := secretKey.Public()

	// Check for user specified purpose.
	if len(tokenPurpose) > 0 {
		purpose = tokenPurpose[0]
	}

	// Sanity check.
	if strings.ToLower(purpose) != "local" && strings.ToLower(purpose) != "public" {
		return nil, errors.New("purpose must be either local or public")
	}

	// Create an instance of Pasty.
	p := &Pasty{
		Purpose:   purpose,
		Expiry:    expires,
		SecretKey: secretKey,
		PublicKey: publicKey,
		LocalKey:  localKey,
	}

	return p, nil
}

// GenerateToken will create and send back a token, with claims. If the receiver's Purpose
// parameter is public, it will create a token signed with the paseto.V4AsymmetricSecretKey
// stored in the receiver as SecretKey. If it is local, it will return a token encrypted with the
// paseto.V4SymmetricKey stored in the receiver as LocalKey.
func (p *Pasty) GenerateToken(expires time.Time, claims map[string]any) (string, error) {
	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(expires)

	for k, v := range claims {
		log.Println("setting claim", k, "to", v)
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	var tkn string

	if p.Purpose == "public" {
		tkn = token.V4Sign(p.SecretKey, nil)
	} else {
		tkn = token.V4Encrypt(p.LocalKey, nil)
	}

	return tkn, nil
}

func (p *Pasty) ValidatePublicToken(tkn string) (bool, error) {
	parser := paseto.NewParser()
	token, err := parser.ParseV4Public(p.PublicKey, tkn, nil)
	if err != nil {
		return false, err
	}

	if p.Issuer != "" {
		iss, err := token.GetIssuer()
		if err != nil {
			return false, err
		}

		if !strings.EqualFold(p.Issuer, iss) {
			return false, errors.New("invalid issuer")
		}
	}

	return true, nil
}
