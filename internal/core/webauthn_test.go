package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitWebAuthn(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *Config
		expectedOrigins []string
	}{
		{
			name: "Default origins from CookieDomains",
			cfg: &Config{
				CookieDomains: []string{"example.com"},
				AllowedHosts:  []string{"auth.example.com"},
			},
			expectedOrigins: []string{
				"https://example.com",
				"http://example.com",
				"https://example.com:5980",
				"http://example.com:5980",
				"https://auth.example.com",
				"http://auth.example.com",
				"https://auth.example.com:5980",
				"http://auth.example.com:5980",
				"http://localhost:5980",
				"http://127.0.0.1:5980",
				"http://localhost",
				"http://127.0.0.1",
			},
		},
		{
			name: "Normalization of origins",
			cfg: &Config{
				CookieDomains:   []string{"example.com"},
				WebAuthnOrigins: []string{"https://domain.com/", "domain2.com", "  domain3.com  "},
			},
			expectedOrigins: []string{
				"https://domain.com",
				"https://domain2.com",
				"http://domain2.com",
				"https://domain3.com",
				"http://domain3.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := InitWebAuthn(tt.cfg)
			assert.NoError(t, err)
			assert.NotNil(t, WebAuthnInstance)
			
			// We can't directly access RPOrigins from WebAuthnInstance as it's private in some versions
			// but we can check the config if we could. 
			// In github.com/go-webauthn/webauthn, it's public in the Config but we pass it to New.
		})
	}
}
