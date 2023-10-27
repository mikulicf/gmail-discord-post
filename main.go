package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	mail "mikulicf/gmail-watcher/pkg/mail"
	"mikulicf/gmail-watcher/pkg/token"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/idtoken"
	"gopkg.in/yaml.v2"
)

type Project struct {
	ProjectID              string `yaml:"project_id"`
	SubscriptionName       string `yaml:"subscription_name"`
	TopicName              string `yaml:"topic_name"`
	TokenPath              string `yaml:"token_path"`
	CredentialsPath        string `yaml:"credentials_path"`
	ServiceCredentialsPath string `yaml:"service_credentials_path"`
	HttpPort               string `yaml:"http_port"`
	HttpsPort              string `yaml:"https_port"`
	ExternalHttpsPort      string `yaml:"external_https_port"`
	DiscordWebhookUrl      string `yaml:"discord_webhook_url"`
	TokenDomain            string `yaml:"token_domain"`
	HttpsKeyPath           string `yaml:"https_key_path"`
	HttpsCertPath          string `yaml:"https_cert_path"`
}

type Config struct {
	Projects []Project `yaml:"projects"`
}

const PayloadIssuer = "accounts.google.com"

type PubSubMessage struct {
	Data        string `json:"data"`
	MessageID   string `json:"message_Id"`
	PublishTime string `json:"publish_time"`
}

type Notification struct {
	Message      PubSubMessage `json:"message"`
	Subscription string        `json:"subscription"`
}

type Credentials struct {
	ClientEmail string `json:"client_email"`
}

func main() {

	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %s\n", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error parsing YAML file: %s\n", err)
	}

	for _, project := range config.Projects {
		if project.ExternalHttpsPort == "" {
			project.ExternalHttpsPort = project.HttpsPort
		}
		var proj Project = project

		go func() {
			newGmail := mail.Gmail{
				CredentialsPath:        proj.CredentialsPath,
				ServiceCredentialsPath: proj.ServiceCredentialsPath,
				TopicName:              proj.TopicName,
				SubscriptionName:       proj.SubscriptionName,
				ProjectID:              proj.ProjectID,
				Token: token.Token{
					Domain:            proj.TokenDomain,
					ExternalHttpsPort: proj.ExternalHttpsPort,
					HttpsPort:         proj.HttpsPort,
					HttpsCertPath:     proj.HttpsCertPath,
					HttpsKeyPath:      proj.HttpsKeyPath,
					TokenFileName:     proj.TokenPath,
				},
			}

			svc, err := newGmail.CreateGmailService()
			if err != nil {
				log.Fatal(err)
			}

			newGmail.WatchInbox(svc)

			// Set up HTTP server
			http.HandleFunc("/notifications", notificationsHandlerFactory(svc, &newGmail, proj))
			http.HandleFunc("/health", healthHandlerFactory(&newGmail))
			go http.ListenAndServe(":"+proj.HttpPort, nil)
			go http.ListenAndServeTLS(":"+proj.HttpsPort, proj.HttpsCertPath, proj.HttpsKeyPath, nil)

			ticker := time.NewTicker(2 * time.Minute)
			quit := make(chan struct{})
			go func() {
				for {
					select {
					case <-ticker.C:
						checkHealth(&newGmail, proj.HttpPort)
					case <-quit:
						ticker.Stop()
						return
					}
				}
			}()

			// Set up re-watch daily
			reWatchTicker := time.NewTicker(time.Hour * 24)
			reWatchQuit := make(chan struct{})
			go func() {
				for {
					select {
					case <-reWatchTicker.C:
						newGmail.ReRegisterWatch()
					case <-reWatchQuit:
						ticker.Stop()
						return
					}
				}
			}()
		}()
	}

	sigChan := make(chan os.Signal, 1)
	// Notify sigChan on Interrupt or Terminate signals
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive a signal
	sig := <-sigChan
	log.Printf("Received signal: %s, exiting...", sig)
}

func getServiceAccountEmail(serviceCredsPath string) (string, error) {
	data, err := os.ReadFile(serviceCredsPath)
	if err != nil {
		return "", err
	}

	var creds Credentials
	err = json.Unmarshal(data, &creds)
	if err != nil {
		return "", err
	}

	return creds.ClientEmail, nil
}

// return errors and handle them
func authenticateRequest(w http.ResponseWriter, r *http.Request, proj Project) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(strings.Split(authHeader, " ")) != 2 {
		return fmt.Errorf("error getting authorization header")
	}
	token := strings.Split(authHeader, " ")[1]
	v, err := idtoken.NewValidator(r.Context())
	if err != nil {
		return err
	}
	payload, err := v.Validate(r.Context(), token, "https://"+proj.TokenDomain+":"+proj.ExternalHttpsPort+"/notifications")
	if err != nil {
		return err
	}
	if payload.Issuer != PayloadIssuer && payload.Issuer != "https://"+PayloadIssuer {
		return fmt.Errorf("unverified payload issuer")
	}

	email, err := getServiceAccountEmail(proj.ServiceCredentialsPath)
	if err != nil {
		return err
	}
	if !(payload.Claims["email"] == email && payload.Claims["email_verified"] == true) {
		return fmt.Errorf("unverified payload email")
	}
	return nil
}

func notificationsHandlerFactory(gmailService *gmail.Service, newGmail *mail.Gmail, proj Project) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := authenticateRequest(w, r, proj)
		if err != nil {
			log.Println(r.Header.Get("CF-Connecting-IP"), r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
			ipAddress := r.Header.Get("X-Forwarded-For")
			if ipAddress == "" {
				ipAddress = r.Header.Get("X-Real-IP")
			}
			if ipAddress == "" {
				ipAddress = r.RemoteAddr
			}
			log.Printf("Unauthorised request from: %s\nError: %s", ipAddress, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Failed reading request body\nError: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Parse the request body
		var notification Notification
		err = json.Unmarshal(bodyBytes, &notification)
		if err != nil {
			log.Printf("Failed parsing JSON data\nError: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		parsedMessageId, err := strconv.ParseUint(notification.Message.MessageID, 10, 64)
		if err != nil {
			log.Printf("Failed parsing message ID\nError: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if newGmail.LastHistoryId != parsedMessageId {

			messageIds, err := newGmail.FetchHistoryIds(gmailService)
			if err != nil {
				log.Printf("Failed fetching history ID\nError: %s", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if messageIds == nil {
				log.Printf("History records empty\n")
				w.WriteHeader(http.StatusOK)
				return
			}
			for _, messageId := range messageIds {
				if slices.Contains(newGmail.ProcessedMessages, messageId) {
					continue
				}
				msg, err := mail.FetchMessage(gmailService, messageId)
				if err != nil {
					log.Printf("Failed fetching message ID: %s\nError: %s", messageId, err)
					continue
				}

				decodedMessage, err := mail.GetMessageData(msg)
				if err != nil {
					log.Printf("Failed decoding message to string Message ID: %s\nError: %s", msg.Id, err)
					continue
				}

				err = postToDiscord(proj.DiscordWebhookUrl, decodedMessage.Body)
				if err != nil {
					log.Printf("Failed posting message to discord Message ID: %s\nError: %s", msg.Id, err)
					continue
				}

				log.Printf("Posted to discord: %s\n", msg.Id)

				newGmail.ProcessedMessages = append(newGmail.ProcessedMessages, messageId)
				newGmail.LastHistoryId = msg.HistoryId
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Notification processed successfully")
	}
}
