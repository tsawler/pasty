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
	Expires    time.Time                    // When does this token expire?
	Purpose    string                       // Must be either local or public.
	PublicKey  paseto.V4AsymmetricPublicKey // The (shareable) public key used for public tokens.
	SecretKey  paseto.V4AsymmetricSecretKey // the private key used for public tokens.
	LocalKey   paseto.V4SymmetricKey        // The key used for local tokens.
	Issuer     string                       // Who issued this token (i.e. example.com).
	Audience   string                       // Who is the token issued for (i.e. example.com).
	Identifier string                       // A private identifier for this token\.
}

func New(tokenPurpose ...string) (*Pasty, error) {
	// Set the default purpose to public. If the parameter tokenPurpose
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

// ValidatePublicToken validates a token signed with a secret key.
// It will also check issuer, audience and identifier (if supplied),
func (p *Pasty) ValidatePublicToken(tkn string) (bool, error) {
	parser := paseto.NewParser()

	if p.Issuer != "" {
		parser.AddRule(paseto.IssuedBy(p.Issuer))
	}

	if p.Audience != "" {
		parser.AddRule(paseto.ForAudience(p.Audience))
	}

	if p.Identifier != "" {
		parser.AddRule(paseto.IdentifiedBy(p.Identifier))
	}

	_, err := parser.ParseV4Public(p.PublicKey, tkn, nil)
	if err != nil {
		return false, err
	}

	return true, nil
}

// ValidateLocalToken validates token with the purpose local.
// It will also check issuer, audience and identifier (if supplied),
func (p *Pasty) ValidateLocalToken(tkn string) (bool, error) {
	parser := paseto.NewParser()

	if p.Issuer != "" {
		parser.AddRule(paseto.IssuedBy(p.Issuer))
	}

	if p.Audience != "" {
		parser.AddRule(paseto.ForAudience(p.Audience))
	}

	if p.Identifier != "" {
		parser.AddRule(paseto.IdentifiedBy(p.Identifier))
	}

	_, err := parser.ParseV4Local(p.LocalKey, tkn, nil)
	if err != nil {
		return false, err
	}

	return true, nil
}
