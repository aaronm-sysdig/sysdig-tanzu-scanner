package oauthtoken

import "time"

type OAuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiryTime   time.Time `json:"-"`
}

// IsValid checks if the OAuth token is still valid based on the current time
func (t *OAuthToken) IsValid() bool {
	return time.Now().Before(t.ExpiryTime)
}

// Refresh updates the OAuth token with a new access token and expiration duration
func (t *OAuthToken) Refresh(newAccessToken string, newExpiresIn int) {
	t.AccessToken = newAccessToken
	t.ExpiryTime = time.Now().Add(time.Second * time.Duration(newExpiresIn))
}
