package mail

import (
	"encoding/base64"

	"google.golang.org/api/gmail/v1"
)

func FetchMessage(gmailService *gmail.Service, messageId string) (*gmail.Message, error) {
	msg, err := gmailService.Users.Messages.Get("me", messageId).Do()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (gm *Gmail) FetchHistoryIds(svc *gmail.Service) ([]string, error) {
	call := svc.Users.History.List("me").StartHistoryId(gm.LastHistoryId)
	historyList, err := call.Do()
	if err != nil {
		return nil, err
	}

	var messageIds []string
	for _, history := range historyList.History {
		for _, message := range history.Messages {
			messageIds = append(messageIds, message.Id)
		}
	}
	return messageIds, nil
}

func GetMessageData(msg *gmail.Message) (DecodedMessage, error) {
	var decodedMessage DecodedMessage
	var rawDecodedText []byte

	for _, part := range msg.Payload.Parts {
		if part.MimeType == "text/plain" {
			// BASE64 URL!!!!!!!!!!!!!!!!!!!!!!! encoded -.-
			var err error
			rawDecodedText, err = base64.URLEncoding.DecodeString(part.Body.Data)
			if err != nil {
				return DecodedMessage{}, err
			}
		}

		for _, header := range msg.Payload.Headers {
			switch header.Name {
			case "Subject":
				decodedMessage.Subject = header.Value
			case "From":
				decodedMessage.From = header.Value
			case "To":
				decodedMessage.To = header.Value
			}
		}
	}
	if rawDecodedText != nil {
		decodedMessage.Body = string(rawDecodedText)
	} else {
		decodedMessage.Body = msg.Snippet
	}
	return decodedMessage, nil
}
