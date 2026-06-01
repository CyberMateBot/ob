package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type RiskThresholds struct {
	Warn int `yaml:"warn"`
	Mute int `yaml:"mute"`
	Ban  int `yaml:"ban"`
}

type NightMode struct {
	Enabled        bool    `yaml:"enabled"`
	StartHour      int     `yaml:"start_hour"`
	EndHour        int     `yaml:"end_hour"`
	RiskMultiplier float64 `yaml:"risk_multiplier"`
}

type Config struct {
	BotToken         string         `yaml:"bot_token"`
	ProxyURL         string         `yaml:"proxy_url"`
	LogChannelID     int64          `yaml:"log_channel_id"`
	NewUserMessages  int            `yaml:"new_user_messages"`
	RiskThresholds   RiskThresholds `yaml:"risk_thresholds"`
	MuteDuration     int            `yaml:"mute_duration"`
	TrustedUsers     []int64        `yaml:"trusted_users"`
	TrustedUsernames []string       `yaml:"trusted_usernames"`
	TrustedChats     []int64        `yaml:"trusted_chats"`
	WhitelistDomains []string       `yaml:"whitelist_domains"`
	BlacklistDomains []string       `yaml:"blacklist_domains"`
	AllowedInvites   []string       `yaml:"allowed_invites"`
	NightMode        NightMode      `yaml:"night_mode"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		NewUserMessages: 5,
		RiskThresholds: RiskThresholds{
			Warn: 40,
			Mute: 60,
			Ban:  80,
		},
		MuteDuration: 86400,
		NightMode: NightMode{
			RiskMultiplier: 1.3,
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Environment variable overrides
	if token := os.Getenv("BOT_TOKEN"); token != "" {
		cfg.BotToken = token
	}
	if proxy := os.Getenv("PROXY_URL"); proxy != "" {
		cfg.ProxyURL = proxy
	}

	if cfg.BotToken == "" {
		return nil, fmt.Errorf("bot_token is required (set in config.yaml or BOT_TOKEN env)")
	}

	// Normalize usernames: strip leading @, lowercase.
	for i, u := range cfg.TrustedUsernames {
		cfg.TrustedUsernames[i] = strings.ToLower(strings.TrimPrefix(u, "@"))
	}

	return cfg, nil
}

func (c *Config) IsTrustedUser(userID int64) bool {
	for _, id := range c.TrustedUsers {
		if id == userID {
			return true
		}
	}
	return false
}

// IsTrustedUsername returns true if the Telegram username (with or without @)
// is in the trusted_usernames list.
func (c *Config) IsTrustedUsername(username string) bool {
	if username == "" {
		return false
	}
	norm := strings.ToLower(strings.TrimPrefix(username, "@"))
	for _, u := range c.TrustedUsernames {
		if u == norm {
			return true
		}
	}
	return false
}

func (c *Config) IsTrustedChat(chatID int64) bool {
	for _, id := range c.TrustedChats {
		if id == chatID {
			return true
		}
	}
	return false
}
