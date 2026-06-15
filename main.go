package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

	if cfg.ProxyURL != "" && (envBool("NO_PROXY") || envBool("DISABLE_PROXY")) {
		log.Println("Proxy disabled via NO_PROXY (recommended on Railway/Render)")
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
		if ok, detail := probeWebhookURL(webhookURL); !ok {
			log.Printf("WARNING: WEBHOOK_URL is not reachable (%s) — Telegram cannot deliver updates", detail)
			log.Printf("WARNING: Fix Railway public domain or set POLLING=true. Falling back to long polling.")
			usePolling = true
			if err := b.DeleteWebhook(); err != nil {
				log.Printf("DeleteWebhook: %v", err)
			}
		} else {
			if err := b.SetWebhook(webhookURL); err != nil {
				log.Printf("Failed to set webhook: %v", err)
			} else {
				log.Printf("Webhook set to %s", webhookURL)
			}
			b.LogWebhookInfo()
		}
	} else {
		log.Println("WEBHOOK_URL is empty — using long polling")
		usePolling = true
		if err := b.DeleteWebhook(); err != nil {
			log.Printf("DeleteWebhook: %v", err)
		}
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
	log.Printf("PORT env=%q", os.Getenv("PORT"))
	addr := "0.0.0.0:" + port
	log.Printf("Listening on %s (mode=%s, health=/health)", addr, modeName(usePolling))

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	if usePolling {
		if err := b.PingTelegram(); err != nil {
			log.Printf("WARNING: Telegram API ping failed: %v", err)
		}
		b.LogWebhookInfo()
		log.Println("Starting long polling…")
		go b.Start()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down…")
}

func modeName(polling bool) string {
	if polling {
		return "polling"
	}
	return "webhook"
}

func envBool(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}

// probeWebhookURL checks that the public Railway/host URL responds (not 404).
func probeWebhookURL(webhookURL string) (bool, string) {
	base := strings.TrimSuffix(webhookURL, "/webhook")
	base = strings.TrimSuffix(base, "/")
	healthURL := base + "/health"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))

	if resp.StatusCode != http.StatusOK {
		return false, fmtStatus(resp.StatusCode, body)
	}
	return true, "ok"
}

func fmtStatus(code int, body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	if s == "" {
		return http.StatusText(code)
	}
	return fmt.Sprintf("%d %s", code, s)
}
