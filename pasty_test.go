package pasty

import (
	"testing"
	"time"
)

func TestPasty_GenerateToken(t *testing.T) {
	tests := []struct {
		name          string
		tokenType     string
		expires       time.Time
		errorExpected bool
		claims        map[string]any
	}{
		{
			name:          "valid token",
			tokenType:     "public",
			expires:       time.Now().Add(time.Hour),
			errorExpected: false,
			claims:        nil,
		},
		{
			name:          "valid with claim",
			tokenType:     "public",
			expires:       time.Now().Add(time.Hour),
			errorExpected: false,
			claims:        map[string]any{"foo": "bar"},
		},
		{
			name:          "valid local token",
			tokenType:     "local",
			expires:       time.Now().Add(time.Hour),
			errorExpected: false,
			claims:        nil,
		},
		{
			name:          "valid local with claim",
			tokenType:     "local",
			expires:       time.Now().Add(time.Hour),
			errorExpected: false,
			claims:        map[string]any{"foo": "bar"},
		},
		{
			name:          "invalid claims payload",
			tokenType:     "local",
			expires:       time.Now().Add(time.Hour),
			errorExpected: true,
			claims:        map[string]any{"foo": func() {}},
		},
	}
	for _, e := range tests {
		t.Run(e.name, func(t *testing.T) {
			p, _ := New(e.tokenType, "example.com", "example.com", "example.com")

			_, err := p.GenerateToken(e.expires, e.claims, "footer data")

			if (err != nil) != e.errorExpected {
				t.Errorf("GenerateToken() %s: error = %v, wantErr %v", e.name, err, e.errorExpected)
				return
			}
		})
	}
}

func TestPasty_ValidatePublicToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		expires time.Time
		claims  map[string]any
		valid   bool
		wantErr bool
	}{
		{
			name:    "valid",
			expires: time.Now().Add(time.Hour),
			valid:   true,
			wantErr: false,
		},
		{
			name:    "expired",
			expires: time.Now().Add(time.Hour * -1),
			valid:   false,
			wantErr: true,
		},
		{
			name:    "invalid with claims",
			expires: time.Now().Add(time.Hour),
			valid:   false,
			wantErr: true,
			claims: map[string]any{
				"issuer":     "example.com",
				"audience":   "wrong.com",
				"identifier": "example.com",
			},
		},
		{
			name:    "valid with claims",
			expires: time.Now().Add(time.Hour),
			valid:   false,
			wantErr: true,
			claims: map[string]any{
				"issuer":     "example.com",
				"audience":   "example.com",
				"identifier": "example.com",
			},
		},
		{
			name:    "invalid signature",
			token:   "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			valid:   false,
			wantErr: true,
		},
	}
	for _, e := range tests {
		t.Run(e.name, func(t *testing.T) {
			token := ""
			p, _ := New("public", "example.com", "audience.com", "some-id")

			if len(e.token) == 0 {
				token, _ = p.GenerateToken(e.expires, e.claims, "")
				if !e.valid {
					token += "1"
				}
			} else {
				token = e.token
			}

			got, err := p.ValidatePublicToken(token)
			if (err != nil) != e.wantErr {
				t.Errorf("ValidatePublicToken() error = %v, wantErr %v", err, e.wantErr)
				return
			}
			if got != e.valid {
				t.Errorf("ValidatePublicToken() got = %v, want %v", got, e.valid)
			}
		})
	}
}

func TestPasty_ValidateLocalToken(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Time
		claims  map[string]any
		valid   bool
		wantErr bool
	}{
		{
			name:    "valid",
			expires: time.Now().Add(time.Hour),
			valid:   true,
			wantErr: false,
		},
		{
			name:    "expired",
			expires: time.Now().Add(time.Hour * -1),
			valid:   false,
			wantErr: true,
		},
		{
			name:    "invalid with claims",
			expires: time.Now().Add(time.Hour),
			valid:   false,
			wantErr: true,
			claims: map[string]any{
				"issuer":     "example.com",
				"audience":   "wrong.com",
				"identifier": "example.com",
			},
		},
		{
			name:    "valid with claims",
			expires: time.Now().Add(time.Hour),
			valid:   false,
			wantErr: true,
			claims: map[string]any{
				"issuer":     "example.com",
				"audience":   "example.com",
				"identifier": "example.com",
			},
		},
	}
	for _, e := range tests {
		t.Run(e.name, func(t *testing.T) {
			p, _ := New("local", "example.com", "example.com", "example.com")

			token, _ := p.GenerateToken(e.expires, e.claims, "")
			if !e.valid {
				token += "1"
			}

			got, err := p.ValidateLocalToken(token)
			if (err != nil) != e.wantErr {
				t.Errorf("ValidateLocalToken() error = %v, wantErr %v", err, e.wantErr)
				return
			}
			if got != e.valid {
				t.Errorf("ValidateLocalToken() got = %v, want %v", got, e.valid)
			}
		})
	}
}

func TestNew(t *testing.T) {

	tests := []struct {
		name    string
		purpose string
		wantErr bool
	}{
		{
			name:    "valid",
			purpose: "public",
			wantErr: false,
		},
		{
			name:    "invalid",
			purpose: "secret",
			wantErr: true,
		},
	}
	for _, e := range tests {
		t.Run(e.name, func(t *testing.T) {
			_, err := New(e.purpose, "example.com", "example.com", "example.com")
			if (err != nil) != e.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, e.wantErr)
				return
			}
		})
	}
}
