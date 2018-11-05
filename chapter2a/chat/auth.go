package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
)

type authHandler struct {
	next http.Handler
}

// random string for oauth2 API calls to protect against CSRF
var oauthStateString = "thisshouldberandom"
var oauthConf = &oauth2.Config{}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("auth")
	if err == http.ErrNoCookie {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}

	if err != nil {
		// some other error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// success - call the next handler
	h.next.ServeHTTP(w, r)
}

// MustAuth wrapper handler force user to login, then passing the user to the chat page
func MustAuth(handler http.Handler) http.Handler {
	return &authHandler{next: handler}
}

// loginHandler handles the third-party login process.
// format: /auth/{action}/{provider}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	segs := strings.Split(r.URL.Path, "/")
	action := segs[2]
	provider := segs[3]
	switch action {
	case "login":
		if provider == "github" {
			oauthConf = &oauth2.Config{
				RedirectURL:  "http://localhost:8080/auth/callback/github",
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
				// select level of access you want https://developer.github.com/v3/oauth/#scopes
				// Scopes:   []string{"user:email", "repo"},
				Endpoint: githuboauth.Endpoint,
			}

			loginURL := oauthConf.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline)
			http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
			log.Println("loginURL: ", loginURL)
		}
	case "callback":
		if provider == "github" {
			handleGitHubCallback(w, r)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Auth action %s not supported", action)
	}
}

// /github_oauth_cb. Called by github after authorization is granted
func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := oauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("oauthConf.Exchange() failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	oauthClient := oauthConf.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	user, _, err := client.Users.Get(oauth2.NoContext, "")
	if err != nil {
		fmt.Printf("client.Users.Get() faled with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Printf("Logged in as GitHub user: %s\n", *user.Login)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
