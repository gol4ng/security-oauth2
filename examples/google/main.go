package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/gol4ng/httpware/v2/auth"
	"github.com/gol4ng/httpware/v2/middleware"
	authentication_http "github.com/gol4ng/security-http/authentication"
	security_oauth_authentication "github.com/gol4ng/security-oauth2/authentication"
	security_oauth_token "github.com/gol4ng/security-oauth2/token"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		RedirectURL:  "http://localhost:8009/googlecallback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writeTemplate(writer, http.StatusOK, "Home", "<a href=\"/googlelogin\">Google Login</a><br>")
	})

	http.HandleFunc("/googlelogin", func(writer http.ResponseWriter, request *http.Request) {
		// generate authenticator random state to verify oauth2callback
		b := make([]byte, 16)
		rand.Read(b)
		state := base64.URLEncoding.EncodeToString(b)

		http.SetCookie(writer, &http.Cookie{Name: "oauthstate", Value: state, Expires: time.Now().Add(365 * 24 * time.Hour)})
		http.Redirect(writer, request, conf.AuthCodeURL(state), http.StatusTemporaryRedirect)
	})

	http.HandleFunc("/googlecallback", func(writer http.ResponseWriter, request *http.Request) {
		code := request.FormValue("code")
		oauthState, _ := request.Cookie("oauthstate")

		if request.FormValue("state") != oauthState.Value {
			writeTemplate(writer, http.StatusBadRequest, "Google callback error", fmt.Errorf("invalid oauth state").Error())
			return
		}
		token, err := conf.Exchange(request.Context(), code)
		if err != nil {
			writeTemplate(writer, http.StatusBadRequest, "Google callback error", fmt.Errorf("code exchange failed: %s", err.Error()).Error())
			return
		}
		rawToken, err := json.Marshal(token)
		http.SetCookie(writer, &http.Cookie{Name: "token", Value: url.QueryEscape(string(rawToken)), Expires: time.Now().Add(365 * 24 * time.Hour)})
		writeTemplate(writer, http.StatusOK, "Google", fmt.Sprintf(
			"<h2>Authenticated</h2><br><p>google redirect you here with rawToken state \"%s\" and code \"%s\"</p><p>we send the cookie \"%s\"</p><a href=\"/protected\">Go view your logged infos</a>",
			oauthState,
			code,
			string(rawToken),
		))
	})

	securemiddleware := middleware.Authentication(
		authentication_http.NewAuthenticatorAdapter(security_oauth_authentication.NewAuthenticator()),
		middleware.WithCredentialFinder(func(request *http.Request) auth.Credential {
			tokenCookie, err := request.Cookie("token")
			if err != nil {
				return nil
			}
			tokenValue, err := url.QueryUnescape(tokenCookie.Value)
			token := &oauth2.Token{}
			err = json.Unmarshal([]byte(tokenValue), token)
			if err != nil {
				return nil
			}
			return security_oauth_token.NewToken(token)
		}),
	)

	http.Handle("/protected", securemiddleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		token := MyTokenGetter(request)
		if token == nil {
			writeTemplate(writer, http.StatusUnauthorized, "Authorized", fmt.Sprintf(
				"get info error: %s",
				"wrong token type",
			))
			return
		}
		response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.GetToken().AccessToken)
		if err != nil {
			writeTemplate(writer, http.StatusUnauthorized, "Authorized", fmt.Sprintf(
				"get info error: %s",
				fmt.Errorf("failed getting user info: %s", err.Error()).Error(),
			))
			return
		}
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			writeTemplate(writer, http.StatusUnauthorized, "Authorized", fmt.Sprintf(
				"get info error: %s",
				fmt.Errorf("failed reading response body: %s", err.Error()).Error(),
			))
			return
		}

		writeTemplate(writer, http.StatusOK, "Authorized", fmt.Sprintf(
			"user info : %s",
			contents,
		))
	})))

	http.ListenAndServe(":8009", nil)
}

func MyTokenGetter(request *http.Request) *security_oauth_token.OauthToken {
	creds := auth.CredentialFromContext(request.Context())
	if creds != nil {
		if token, ok := creds.(*security_oauth_token.OauthToken); ok {
			return token
		}
	}
	return nil
}

type Page struct {
	Title   string
	Content template.HTML
}

const html = `
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>{{.Title}}</title>
    </head>
    <body>
        <h1>{{.Title}}</h1>
        <article id="content">
            {{.Content}}
        </article>
    </body>
</html>`

var tpl = template.Must(template.New("name").Parse(html))

func writeTemplate(writer http.ResponseWriter, code int, title string, content string) {
	tpl.Execute(writer, &Page{
		Title:   title,
		Content: template.HTML(content),
	})
	writer.WriteHeader(code)
}
