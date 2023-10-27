package main

import (
	"fmt"
	"log"
	"mikulicf/gmail-watcher/pkg/mail"
	"net/http"
)

func healthHandlerFactory(gm *mail.Gmail) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		active := gm.CheckWatchStatus()
		if active {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Status: ok")
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Status: error")
			gm.ReRegisterWatch()
		}
	}
}

func checkHealth(gm *mail.Gmail, httpPort string) {
	resp, err := http.Get("http://localhost:" + httpPort + "/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Printf("Status: %s\n", resp.Status)
		gm.ReRegisterWatch()
	}
}
