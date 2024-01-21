package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
)

func Test_generateAppleSecret(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	keyID := "kid"
	clientID := "clientID"
	teamID := "teamID"
	expiresInSeconds := int64(3600)

	key := jose.JSONWebKey{
		Algorithm: string(jose.ES256),
		Key:       k,
		Use:       "sig",
		KeyID:     keyID,
	}

	signingKey := jose.SigningKey{Key: key, Algorithm: jose.ES256}
	got, err := generateAppleSecret(signingKey, keyID, clientID, teamID, expiresInSeconds)
	assert.NoError(t, err)
	assert.NotNil(t, got)

	token, err := jwt.ParseSigned(got)
	assert.NoError(t, err)
	assert.NotNil(t, token)

	claims := map[string]interface{}{}

	publicKey := jose.JSONWebKey{Key: &k.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}

	err = token.Claims(publicKey, &claims)
	assert.NoError(t, err)

	assert.Equal(t, teamID, claims["iss"])
	assert.Equal(t, clientID, claims["sub"])
	assert.Equal(t, "https://appleid.apple.com", claims["aud"])
	assert.Less(t, float64(time.Now().Unix()+expiresInSeconds-1), claims["exp"].(float64))
	assert.Less(t, float64(time.Now().Unix()-1), claims["iat"].(float64))
}
