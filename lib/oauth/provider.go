package oauth

import (
	"github.com/go-jose/go-jose/v3"
	"golang.org/x/oauth2"
)

// Provider is a struct wrapping the necessary bits to integrate an OAuth2 provider with AuthN
type Provider struct {
	config         *oauth2.Config
	UserInfo       UserInfoFetcher
	signingKey     jose.SigningKey
	secretOverride func() (string, error)
}

// UserInfo is the minimum necessary needed from an OAuth Provider to connect with AuthN accounts
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// UserInfoFetcher is the function signature for fetching UserInfo from a Provider
type UserInfoFetcher = func(t *oauth2.Token) (*UserInfo, error)

// NewProvider returns a properly configured Provider
func NewProvider(config *oauth2.Config, userInfo UserInfoFetcher, signingKey jose.SigningKey) *Provider {
	return &Provider{config: config, UserInfo: userInfo, signingKey: signingKey}
}

// NewProviderWithSecretOverride returns a properly configured Provider
func NewProviderWithSecretOverride(config *oauth2.Config, userInfo UserInfoFetcher, signingKey jose.SigningKey, secretOverride func() (string, error)) *Provider {
	return &Provider{config: config, UserInfo: userInfo, signingKey: signingKey, secretOverride: secretOverride}
}

// Config returns a complete oauth2.Config after injecting the RedirectURL
func (p *Provider) Config(redirectURL string) (*oauth2.Config, error) {
	// TODO: return errors instead of panicking
	secret, err := p.Secret()
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: secret,
		Scopes:       p.config.Scopes,
		Endpoint:     p.config.Endpoint,
		RedirectURL:  redirectURL,
	}, nil
}

func (p *Provider) Secret() (string, error) {
	if p.secretOverride != nil {
		return p.secretOverride()
	}
	return p.config.ClientSecret, nil
}

func (p *Provider) SigningKey() jose.SigningKey {
	return p.signingKey
}
