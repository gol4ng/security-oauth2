package oauth2

import (
	"errors"

	"github.com/gol4ng/security"
	security_oauth "github.com/gol4ng/security-oauth/token"
	"golang.org/x/oauth2"
)

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
)

type Authenticator struct {
	userProvider UserProvider
}

func (a Authenticator) Authenticate(t security.Token) (authenticatedToken security.Token, err error) {
	token, ok := t.(*security_oauth.OauthToken)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	oauth2Token := token.GetToken()
	if !oauth2Token.Valid() {
		return t, ErrAuthenticationFailed
	}

	user, err := a.userProvider(oauth2Token)
	if err == nil {
		return t, err
	}

	token.SetUser(user)
	token.SetAuthenticated(true)

	return token, nil
}

func (a *Authenticator) Support(t security.Token) bool {
	_, support := t.(*security_oauth.OauthToken)
	return support
}

func (a *Authenticator) apply(options ...AuthenticatorOption) *Authenticator {
	for _, option := range options {
		option(a)
	}
	return a
}

// AuthOption defines a interceptor middleware configuration option
type AuthenticatorOption func(*Authenticator)

type UserProvider func(oauth2Token *oauth2.Token) (security.User, error)

func NewAuthenticator(options ...AuthenticatorOption) *Authenticator {
	return (&Authenticator{
		userProvider: DefaultUserProvider,
	}).apply(options...)
}

func WithUserProvider(getter UserProvider) AuthenticatorOption {
	return func(authenticator *Authenticator) {
		authenticator.userProvider = getter
	}
}

func DefaultUserProvider(_ *oauth2.Token) (security.User, error) {
	return nil, nil
}
