package token

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
)

type TokenRefresher struct {
	tk     *Token
	config *oauth2.Config
}

type Token struct {
	Domain            string
	ExternalHttpsPort string
	HttpsPort         string
	HttpsCertPath     string
	HttpsKeyPath      string
	TokenFileName     string
}

func (r *TokenRefresher) Token() (*oauth2.Token, error) {
	var token *oauth2.Token
	if _, err := os.Stat(r.tk.TokenFileName); err == nil {
		token, err = r.tk.TokenFromFile(r.tk.TokenFileName)
		if err != nil {
			return nil, err
		}
	} else {
		token, err = r.tk.GetTokenFromWeb(r.config)
		if err != nil {
			return nil, err
		}
	}

	if token.Valid() {
		return token, nil
	}

	// refresh the token
	ts := r.config.TokenSource(context.Background(), token)
	token, err := ts.Token()
	if err != nil {
		return nil, err
	}

	// save the new token
	SaveToken(r.tk.TokenFileName, token)

	return token, nil
}

func SaveToken(file string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", file)
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func (tk *Token) TokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)
	return token, err
}

func (tk *Token) GetTokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {
	// Create a new redirect URI
	redirectURL := "https://localhost:" + tk.ExternalHttpsPort + "/auth/callback"
	config.RedirectURL = redirectURL

	// Generate the OAuth URL
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your web browser: \n%v\n", authURL)

	// Create a channel to signal completion
	codeChan := make(chan string)

	// Start the HTTP server
	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		codeChan <- code
	})

	go http.ListenAndServeTLS(":"+tk.HttpsPort, tk.HttpsCertPath, tk.HttpsKeyPath, nil)

	// Wait for the auth code
	authCode := <-codeChan

	// Exchange the auth code for a token
	token, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	SaveToken(tk.TokenFileName, token)

	return token, err
}

func TokenSource(ctx context.Context, tk *Token, config *oauth2.Config) oauth2.TokenSource {
	return &TokenRefresher{
		tk:     tk,
		config: config,
	}
}
