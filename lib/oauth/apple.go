package oauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/oauth2"
)

type appleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type appleKeyResponse struct {
	Keys []appleKey `json:"keys"`
}

type appleKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

// NewAppleProvider returns a AuthN integration for sign-in with Apple OAuth
func NewAppleProvider(credentials *Credentials) (*Provider, error) {
	config := &oauth2.Config{
		ClientID: credentials.ID,
		// ClientSecret for apple is built using generateAppleSecret
		// this function is passed to the provider for use as an override
		// and built fresh on each call to provider.Config(returnURL).
		ClientSecret: "",
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://appleid.apple.com/auth/oauth2/v2/authorize",
			TokenURL:  "https://appleid.apple.com/auth/oauth2/v2/token",
			AuthStyle: 0,
		},
	}

	var (
		keyID        string
		teamID       string
		expiresInStr string
		expiresIn    int64
		found        bool
		constructErr error
	)

	if keyID, found = credentials.Additional["keyID"]; !found {
		return nil, fmt.Errorf("missing keyID")
	}

	if teamID, found = credentials.Additional["teamID"]; !found {
		return nil, fmt.Errorf("missing teamID")
	}

	if expiresInStr, found = credentials.Additional["expirySeconds"]; !found {
		panic("missing expirySeconds")
	} else {
		expiresIn, constructErr = strconv.ParseInt(expiresInStr, 10, 0)
		if constructErr != nil {
			return nil, constructErr
		}
	}

	// this has already been hex decoded
	// TODO: document that it needs to be full PEM block
	keyBlock, _ := pem.Decode(credentials.SigningKey)
	key, constructErr := x509.ParseECPrivateKey(keyBlock.Bytes)
	if constructErr != nil {
		return nil, fmt.Errorf("failed to parse EC key: %v", constructErr)
	}

	signingKey := jose.SigningKey{Key: jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: "ES256",
		Use:       "sig",
	}, Algorithm: jose.ES256}

	keyStore := &appleSigningKeyStore{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		keys: make(map[string]*rsa.PublicKey),
	}

	//TODO: cleanup scopes etc
	getAppleUserInfo := func(t *oauth2.Token) (*UserInfo, error) {
		client := &http.Client{
			Timeout: 10 * time.Second,
		}

		// TODO: we might be able to use this
		/*
			idToken := t.Extra("id_token").(string)
			decodedIDToken, err := base64.StdEncoding.DecodeString(idToken)
		*/

		// instead of using the refresh token to retrieve the ID token
		secret, err := generateAppleSecret(signingKey, keyID, config.ClientID, teamID, expiresIn)
		if err != nil {
			return nil, err
		}

		resp, err := client.PostForm(config.Endpoint.TokenURL, url.Values{
			"client_id":     {credentials.ID},
			"client_secret": {secret},
			"grant_type":    {"refresh_token"},
			"refresh_token": {t.RefreshToken},
		})

		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var tokenResponse appleTokenResponse
		err = json.Unmarshal(body, &tokenResponse)

		if err != nil {
			return nil, err
		}

		decodedIDToken, err := base64.StdEncoding.DecodeString(tokenResponse.IDToken)

		// from here would remain the same
		if err != nil {
			return nil, fmt.Errorf("failed to decode apple ID token: %v", err)
		}
		parsedIDToken, err := jwt.ParseSigned(string(decodedIDToken))

		if err != nil {
			return nil, err
		}

		var hdr *jose.Header

		for _, th := range parsedIDToken.Headers {
			if th.Algorithm == "RS256" {
				hdr = &th
				break
			}
		}

		if hdr == nil {
			return nil, fmt.Errorf("no RS256 key header")
		}

		key, err := keyStore.Get(hdr.KeyID)

		if err != nil {
			return nil, err
		}

		claims := make(map[string]interface{})
		err = parsedIDToken.Claims(key, &claims)

		if err != nil {
			return nil, fmt.Errorf("failed to verify claims: %v", err)
		}

		//TODO: need to do anything with claims[nonce]

		if iss, ok := claims["iss"]; !ok || !strings.Contains(iss.(string), "https://appleid.apple.com") {
			return nil, fmt.Errorf("invalid or missing issuer")
		}

		if aud, ok := claims["aud"]; !ok || aud.(string) == config.ClientID {
			return nil, fmt.Errorf("invalid or missing audience")
		}

		if exp, ok := claims["exp"]; !ok {
			return nil, fmt.Errorf("missing exp")
		} else {
			switch v := exp.(type) {
			case float64:
				if int64(v) < time.Now().Unix() {
					return nil, fmt.Errorf("token expired")
				}
			case int:
				if int64(v) < time.Now().Unix() {
					return nil, fmt.Errorf("token expired")
				}
			}
		}

		id, ok := claims["sub"]

		if !ok {
			return nil, fmt.Errorf("missing claim 'sub'")
		}

		email, ok := claims["email"]

		if !ok {
			return nil, fmt.Errorf("missing claim 'email'")
		}

		return &UserInfo{
			ID:    id.(string),
			Email: email.(string),
		}, nil
	}

	return NewProviderWithSecretOverride(config, getAppleUserInfo, signingKey, func() (string, error) {
		return generateAppleSecret(signingKey, keyID, config.ClientID, teamID, expiresIn)
	}), nil
}

// generateAppleSecret creates a signed JWT as specified at
// https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
func generateAppleSecret(key jose.SigningKey, keyID, clientID, teamID string, expiresInSeconds int64) (string, error) {
	if key.Algorithm != jose.ES256 {
		return "", fmt.Errorf("expected ES256 signing key got %s", key.Algorithm)
	}

	signer, err := jose.NewSigner(key, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": keyID,
			"alg": key.Algorithm,
		},
	})

	if err != nil {
		return "", fmt.Errorf("failed to create signer: %v", err)
	}

	return jwt.Signed(signer).Claims(map[string]interface{}{
		"iss": teamID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Duration(expiresInSeconds) * time.Second).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": clientID,
	}).CompactSerialize() // TODO: compact or full?  Do we need to encode further?
}

type appleSigningKeyStore struct {
	client *http.Client
	keys   map[string]*rsa.PublicKey
}

func (a *appleSigningKeyStore) Get(keyID string) (*rsa.PublicKey, error) {
	itm, got := a.keys[keyID]
	if got {
		return itm, nil
	}

	a.Refresh()

	itm, got = a.keys[keyID]
	if got {
		return itm, nil
	}

	return nil, fmt.Errorf("key %s not found", keyID)
}

func (a *appleSigningKeyStore) Refresh() error {
	var x appleKeyResponse
	_ = x.Keys
	keysResp, keysErr := a.client.Get("https://appleid.apple.com/auth/keys")
	if keysErr != nil {
		return fmt.Errorf("failed to fetch apple keys: %v", keysErr)
	}

	keysBody, keysErr := io.ReadAll(keysResp.Body)
	if keysErr != nil {
		return fmt.Errorf("failed to read apple keys: %v", keysErr)
	}

	keys := appleKeyResponse{}
	keysErr = json.Unmarshal(keysBody, &keys)

	if keysErr != nil {
		return fmt.Errorf("failed to unmarshal apple keys: %v", keysErr)
	}

	newKeys := make(map[string]*rsa.PublicKey, len(keys.Keys))

	for _, key := range keys.Keys {
		// build key and place in new map
		publicKey := new(rsa.PublicKey)
		n := new(big.Int)
		nbytes, _ := base64.URLEncoding.DecodeString(key.N + "=")
		publicKey.N = n.SetBytes(nbytes)

		var eInt int
		ebytes, _ := base64.RawURLEncoding.DecodeString(key.E)
		for _, v := range ebytes {
			eInt = eInt << 8
			eInt = eInt | int(v)
		}

		publicKey.E = eInt

		newKeys[key.Kid] = publicKey
	}

	a.keys = newKeys

	return nil
}
