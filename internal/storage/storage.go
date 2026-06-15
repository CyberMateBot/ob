package storage

import (
	"fmt"
	"sync"
	"time"
)

const (
	recentHashWindow = 50 // max recent hashes per chat
	recentHashTTL    = 30 * time.Minute
	adminCacheTTL    = 5 * time.Minute
)

// UserState tracks per-user moderation data.
type UserState struct {
	MessageCount int
	MutedUntil   time.Time
	Banned       bool
}

// DeletedMessage records a message that was removed by the bot.
type DeletedMessage struct {
	ChatID    int64
	MessageID int
	UserID    int64
	Username  string
	Text      string
	Reason    string
	Score     int
	DeletedAt time.Time
}

type adminEntry struct {
	isAdmin   bool
	expiresAt time.Time
}

type recentHash struct {
	hash   string
	userID int64
	at     time.Time
}

// Storage holds all in-memory moderation state.
type Storage struct {
	mu           sync.RWMutex
	users        map[int64]*UserState
	adminCache   map[string]adminEntry      // key "chatID:userID"
	deleted      map[string]*DeletedMessage // key "chatID:msgID"
	recentHashes map[int64][]recentHash     // chatID → rolling window
}

// New creates an empty Storage.
func New() *Storage {
	return &Storage{
		users:        make(map[int64]*UserState),
		adminCache:   make(map[string]adminEntry),
		deleted:      make(map[string]*DeletedMessage),
		recentHashes: make(map[int64][]recentHash),
	}
}

// ── User state ────────────────────────────────────────────────────

// GetOrCreateUser returns a copy of the user's state (safe for reading).
func (s *Storage) GetOrCreateUser(userID int64) UserState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		s.users[userID] = &UserState{}
	}
	return *s.users[userID]
}

// IncrementMessageCount increments the seen-message counter for a user.
func (s *Storage) IncrementMessageCount(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		s.users[userID] = &UserState{}
	}
	s.users[userID].MessageCount++
}

// SetMuted marks a user as muted until the given time.
func (s *Storage) SetMuted(userID int64, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureUser(userID)
	s.users[userID].MutedUntil = until
}

// SetBanned marks a user as banned.
func (s *Storage) SetBanned(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureUser(userID)
	s.users[userID].Banned = true
}

// ClearModeration clears mute/ban flags after manual restore.
func (s *Storage) ClearModeration(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[userID]; ok {
		u.MutedUntil = time.Time{}
		u.Banned = false
	}
}

func (s *Storage) ensureUser(userID int64) {
	if _, ok := s.users[userID]; !ok {
		s.users[userID] = &UserState{}
	}
}

// ── Admin cache ───────────────────────────────────────────────────

// GetAdminCache returns (isAdmin, found) from the local cache.
func (s *Storage) GetAdminCache(chatID, userID int64) (bool, bool) {
	key := adminKey(chatID, userID)
	s.mu.RLock()
	e, ok := s.adminCache[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return false, false
	}
	return e.isAdmin, true
}

// SetAdminCache stores admin status for the given user in the given chat.
func (s *Storage) SetAdminCache(chatID, userID int64, isAdmin bool) {
	key := adminKey(chatID, userID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adminCache[key] = adminEntry{
		isAdmin:   isAdmin,
		expiresAt: time.Now().Add(adminCacheTTL),
	}
}

func adminKey(chatID, userID int64) string {
	return fmt.Sprintf("%d:%d", chatID, userID)
}

// ── Deleted message log ───────────────────────────────────────────

// SaveDeleted persists a record of a deleted message.
func (s *Storage) SaveDeleted(chatID int64, msgID int, userID int64, username, text, reason string, score int) {
	key := fmt.Sprintf("%d:%d", chatID, msgID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted[key] = &DeletedMessage{
		ChatID:    chatID,
		MessageID: msgID,
		UserID:    userID,
		Username:  username,
		Text:      text,
		Reason:    reason,
		Score:     score,
		DeletedAt: time.Now(),
	}
}

// GetDeleted retrieves a previously saved deleted-message record.
func (s *Storage) GetDeleted(chatID int64, msgID int) (*DeletedMessage, bool) {
	key := fmt.Sprintf("%d:%d", chatID, msgID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.deleted[key]
	return d, ok
}

// ── Duplicate detection ───────────────────────────────────────────

// IsDuplicate returns true if this (chatID, userID, hash) combination was
// seen within the recent-hash TTL window.
func (s *Storage) IsDuplicate(chatID, userID int64, hash string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-recentHashTTL)
	for _, h := range s.recentHashes[chatID] {
		if h.hash == hash && h.userID == userID && h.at.After(cutoff) {
			return true
		}
	}
	return false
}

// RecordMessage adds a message hash to the rolling window for a chat.
func (s *Storage) RecordMessage(chatID, userID int64, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	window := append(s.recentHashes[chatID], recentHash{
		hash:   hash,
		userID: userID,
		at:     time.Now(),
	})
	if len(window) > recentHashWindow {
		window = window[len(window)-recentHashWindow:]
	}
	s.recentHashes[chatID] = window
}
