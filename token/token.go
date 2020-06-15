package oauth2

import (
	security_token "github.com/gol4ng/security/token"
	"golang.org/x/oauth2"
)

type OauthToken struct {
	security_token.Token

	oauth2Token *oauth2.Token
}

func (t *OauthToken) GetToken() *oauth2.Token {
	return t.oauth2Token
}

func NewToken(oauth2Token *oauth2.Token) *OauthToken {
	return &OauthToken{
		oauth2Token: oauth2Token,
	}
}
