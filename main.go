package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"odysseyshield/internal/bot"
	"odysseyshield/internal/config"
	"odysseyshield/internal/storage"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func main() {
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store := storage.New()

	b, err := bot.New(cfg, store)
	if err != nil {
		log.Fatalf("bot init: %v", err)
	}

	usePolling := envBool("POLLING")
	webhookURL := strings.TrimSpace(os.Getenv("WEBHOOK_URL"))
	if usePolling {
		if err := b.DeleteWebhook(); err != nil {
			log.Printf("DeleteWebhook: %v", err)
		} else {
			log.Println("Webhook removed, using long polling")
		}
	} else if webhookURL != "" {
		if err := b.SetWebhook(webhookURL); err != nil {
			log.Printf("Failed to set webhook: %v", err)
		} else {
			log.Printf("Webhook set to %s", webhookURL)
		}
		b.LogWebhookInfo()
	} else {
		log.Println("WARNING: WEBHOOK_URL is empty and POLLING is not set — bot will not receive updates")
	}

	log.Println("Odyssey Shield (MVP) started")

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	if !usePolling && webhookURL != "" {
		mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var update tgbotapi.Update
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				log.Printf("Failed to decode update: %v", err)
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}

			log.Printf("Webhook update: id=%d message=%t callback=%t",
				update.UpdateID, update.Message != nil, update.CallbackQuery != nil)

			b.HandleUpdate(update)
			w.WriteHeader(http.StatusOK)
		})
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := "0.0.0.0:" + port
	log.Printf("Listening on %s (health: /health)", addr)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	if usePolling {
		log.Println("Starting long polling…")
		go b.Start()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down…")
}

func envBool(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}
