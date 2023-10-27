package mail

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"cloud.google.com/go/pubsub"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"

	toks "mikulicf/gmail-watcher/pkg/token"
)

func (gm *Gmail) WatchInbox(gmailService *gmail.Service) {
	watchRequest := &gmail.WatchRequest{
		LabelIds:  []string{GMAIL_LABEL},
		TopicName: gm.TopicName,
	}

	watchResponse, err := gmailService.Users.Watch(GMAIL_USERID, watchRequest).Do()
	if err != nil {
		log.Fatalf("Unable to create watch: %v", err)
	}

	profile, err := gmailService.Users.GetProfile("me").Do()
	if err != nil {
		log.Fatalf("Unable to get profile: %v", err)
	}

	fmt.Printf("Watch created on inbox %s, historyId: %d\n", profile.EmailAddress, watchResponse.HistoryId)

	gm.LastHistoryId = watchResponse.HistoryId

}

func (gm *Gmail) CheckWatchStatus() bool {
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, gm.ProjectID, option.WithCredentialsFile(gm.ServiceCredentialsPath))
	if err != nil {
		log.Fatalf("Could not create Pub/Sub client: %v", err)
	}
	defer client.Close()

	subs := strings.Split(gm.SubscriptionName, "/")
	sub := client.Subscription(subs[len(subs)-1])
	subConfig, err := sub.Config(ctx)
	if err != nil {
		log.Println("Could not get subscription config:", err)
		return false
	}

	return (subConfig.State == pubsub.SubscriptionStateActive)
}

func (gm *Gmail) CreateGmailService() (*gmail.Service, error) {
	creds, err := os.ReadFile(gm.CredentialsPath)
	if err != nil {
		log.Println(err)
	}
	config, err := google.ConfigFromJSON(creds, gmail.GmailModifyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	ctx := context.Background()

	tk := gm.Token

	ts := toks.TokenSource(context.Background(), &tk, config)
	token, err := ts.Token()
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}

	client := config.Client(ctx, token)
	svc, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return svc, nil
}

func (gm *Gmail) ReRegisterWatch() {

	svc, err := gm.CreateGmailService()
	if err != nil {
		log.Println(err)
	}
	gm.ProcessedMessages = nil
	gm.WatchInbox(svc)
}
