package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type DiscordWebhook struct {
	Content string `json:"content"`
}

func postToDiscord(webhook string, subject string, body string) error {
	webhookBody := &DiscordWebhook{Content: fmt.Sprintf("%s\n%s", subject, body)}
	jsonData, err := json.Marshal(webhookBody)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
