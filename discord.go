package main

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type DiscordWebhook struct {
	Content string `json:"content"`
}

func postToDiscord(webhook string, message string) error {
	webhookBody := &DiscordWebhook{Content: message}
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
