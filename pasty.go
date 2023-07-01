package pasty

import (
	"aidanwoods.dev/go-paseto"
	"errors"
	"strings"
	"time"
)

// Pasty is the main type for this module. Create a variable of this type
// by calling the New function.
type Pasty struct {
	Options Options
}

// Options holds the options for our Pasty type.
type Options struct {
	PublicKey  paseto.V4AsymmetricPublicKey // The (shareable) public key used for public tokens.
	SecretKey  paseto.V4AsymmetricSecretKey // the (secret) private key used for public tokens.
	LocalKey   paseto.V4SymmetricKey        // The key used for local tokens.
	Purpose    string                       // Must be either local or public.
	Issuer     string                       // Who issued this token (i.e. example.com).
	Audience   string                       // Who is the token issued for (i.e. example.com).
	Identifier string                       // A private identifier for this token.
}

// New creates a new instance of the Pasty type.
func New(purpose, issuer, audience, identifier string) (*Pasty, error) {
	// Generate the keys for our type.
	secretKey := paseto.NewV4AsymmetricSecretKey()
	localKey := paseto.NewV4SymmetricKey()
	publicKey := secretKey.Public()

	options := Options{
		PublicKey:  publicKey,
		SecretKey:  secretKey,
		LocalKey:   localKey,
		Purpose:    purpose,
		Issuer:     issuer,
		Audience:   audience,
		Identifier: identifier,
	}

	// Sanity check.
	if strings.ToLower(purpose) != "local" && strings.ToLower(purpose) != "public" {
		return nil, errors.New("the Options.Purpose value must be either local or public")
	}

	// Create an instance of Pasty.
	p := &Pasty{
		Options: options,
	}

	return p, nil
}

// GenerateToken will create and send back a token, with claims. If the receiver's Purpose
// parameter is public, it will create a token signed with the paseto.V4AsymmetricSecretKey
// stored in the receiver as SecretKey. If it is local, it will return a token encrypted with the
// paseto.V4SymmetricKey stored in the receiver as LocalKey.
func (p *Pasty) GenerateToken(expires time.Time, claims map[string]any, footer string) (string, error) {
	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(expires)
	token.SetJti(p.Options.Identifier)
	token.SetIssuer(p.Options.Issuer)
	token.SetAudience(p.Options.Audience)
	if len(footer) > 0 {
		token.SetFooter([]byte(footer))
	}

	for k, v := range claims {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	var tkn string

	if p.Options.Purpose == "public" {
		tkn = token.V4Sign(p.Options.SecretKey, nil)
	} else {
		tkn = token.V4Encrypt(p.Options.LocalKey, nil)
	}

	return tkn, nil
}

// ValidatePublicToken validates a token signed with a secret key.
// It will also check issuer, audience and identifier (if supplied),
func (p *Pasty) ValidatePublicToken(tkn string) (bool, error) {
	parser := paseto.NewParser()

	if p.Options.Issuer != "" {
		parser.AddRule(paseto.IssuedBy(p.Options.Issuer))
	}

	if p.Options.Audience != "" {
		parser.AddRule(paseto.ForAudience(p.Options.Audience))
	}

	if p.Options.Identifier != "" {
		parser.AddRule(paseto.IdentifiedBy(p.Options.Identifier))
	}

	_, err := parser.ParseV4Public(p.Options.PublicKey, tkn, nil)
	if err != nil {
		return false, err
	}

	return true, nil
}

// ValidateLocalToken validates token with the purpose local.
// It will also check issuer, audience and identifier (if supplied),
func (p *Pasty) ValidateLocalToken(tkn string) (bool, error) {
	parser := paseto.NewParser()

	if p.Options.Issuer != "" {
		parser.AddRule(paseto.IssuedBy(p.Options.Issuer))
	}

	if p.Options.Audience != "" {
		parser.AddRule(paseto.ForAudience(p.Options.Audience))
	}

	if p.Options.Identifier != "" {
		parser.AddRule(paseto.IdentifiedBy(p.Options.Identifier))
	}

	_, err := parser.ParseV4Local(p.Options.LocalKey, tkn, nil)
	if err != nil {
		return false, err
	}

	return true, nil
}
