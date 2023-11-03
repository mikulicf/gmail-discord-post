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
	"regexp"
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
				log.Printf("Failed creating service for project %s\n%s", proj.ProjectID, err)
			}

			newGmail.WatchInbox(svc)

			// Set up HTTP server
			http.HandleFunc("/notifications/"+proj.ProjectID, notificationsHandlerFactory(svc, &newGmail, proj))
			http.HandleFunc("/health/"+proj.ProjectID, healthHandlerFactory(&newGmail))
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
	payload, err := v.Validate(r.Context(), token, "https://"+proj.TokenDomain+":"+proj.ExternalHttpsPort+"/notifications/"+proj.ProjectID)
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

				log.Println(decodedMessage.Body)

				log.Printf("Processing mail %s on inbox %s", messageId, newGmail.InboxAdress)

				if strings.Contains(strings.ToLower(decodedMessage.Body), "steam") && strings.Contains(strings.ToLower(decodedMessage.Body), "code") {
					steamUsernameRegex1 := regexp.MustCompile(`(?:.*?)*?(\b\w*?\b),`)
					steamCodeRegex1 := regexp.MustCompile(`(?m)Request made from(?:.*?)*?(?:.*?\n)*?([A-Z0-9]{5})`)

					// Try matching Steam username and code with first regex pattern
					steamUsernameMatch := steamUsernameRegex1.FindStringSubmatch(decodedMessage.Body)
					steamCodeMatch := steamCodeRegex1.FindStringSubmatch(decodedMessage.Body)

					if steamUsernameMatch != nil && steamCodeMatch != nil {
						subject := "Steam: " + steamUsernameMatch[1]
						body := "Code: " + steamCodeMatch[1]
						err = postToDiscord(proj.DiscordWebhookUrl, subject, body)
						if err != nil {
							log.Printf("Failed posting message to discord Message ID: %s\nError: %s", msg.Id, err)
							continue
						}
					} else {
						log.Println("Unable to find steam regexp match.")
					}

				} else if strings.Contains(strings.ToLower(decodedMessage.Body), "epic") && strings.Contains(strings.ToLower(decodedMessage.Body), "code") {

					epicCodeRegex := regexp.MustCompile(`code (\d+)`)
					epicCodeMatch := epicCodeRegex.FindStringSubmatch(decodedMessage.Body)
					if epicCodeMatch != nil {
						subject := "Epic: " + decodedMessage.To
						body := "Code: " + epicCodeMatch[1]
						err = postToDiscord(proj.DiscordWebhookUrl, subject, body)
						if err != nil {
							log.Printf("Failed posting message to discord Message ID: %s\nError: %s", msg.Id, err)
							continue
						}

					} else {
						log.Println("Unable to find epic regexp match.")
					}

				} else if strings.Contains(strings.ToLower(decodedMessage.Body), "battle.net") && strings.Contains(strings.ToLower(decodedMessage.Body), "code") {

					battleAccountNameRegex := regexp.MustCompile(`If (.*?) isn&#39;t your account name,`)
					battleCodeRegex := regexp.MustCompile(`code: (\w+)`)

					battleAccountNameMatch := battleAccountNameRegex.FindStringSubmatch(decodedMessage.Body)
					battleCodeMatch := battleCodeRegex.FindStringSubmatch(decodedMessage.Body)

					if battleAccountNameMatch != nil && battleCodeMatch != nil {
						subject := "Battle.net: " + battleAccountNameMatch[1]
						body := "Code: " + battleCodeMatch[1]
						err = postToDiscord(proj.DiscordWebhookUrl, subject, body)
						if err != nil {
							log.Printf("Failed posting message to discord Message ID: %s\nError: %s", msg.Id, err)
							continue
						}
					} else {
						log.Println("Unable to find battle.net regexp match.")
					}

				} else if strings.Contains(strings.ToLower(decodedMessage.From), "rockstar") && strings.Contains(strings.ToLower(decodedMessage.Body), "code") {
					rockstarCodeRegex := regexp.MustCompile(`\b(\d{6})\b`)
					rockstarCodeMatch := rockstarCodeRegex.FindStringSubmatch(decodedMessage.Body)

					if rockstarCodeMatch != nil {
						subject := "Rockstar: " + decodedMessage.To
						body := "Code: " + rockstarCodeMatch[1]
						err = postToDiscord(proj.DiscordWebhookUrl, subject, body)
						if err != nil {
							log.Printf("Failed posting message to discord Message ID: %s\nError: %s", msg.Id, err)
							continue
						}
					} else {
						log.Println("Unable to rockstar find regexp match.")
					}
				}

				newGmail.ProcessedMessages = append(newGmail.ProcessedMessages, messageId)
				newGmail.LastHistoryId = msg.HistoryId
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Notification processed successfully")
	}
}
