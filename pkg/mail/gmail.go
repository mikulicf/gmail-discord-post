package mail

import "mikulicf/gmail-watcher/pkg/token"

const GMAIL_LABEL = "INBOX"
const GMAIL_USERID = "me"

type Gmail struct {
	InboxAdress            string
	LastHistoryId          uint64
	ProcessedMessages      []string
	CredentialsPath        string
	ServiceCredentialsPath string
	TopicName              string
	SubscriptionName       string
	ProjectID              string
	Token                  token.Token
}

type DecodedMessage struct {
	Body    string
	Subject string
	From    string
	To      string
}
