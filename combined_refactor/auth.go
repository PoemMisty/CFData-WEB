package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const sessionCookieName = "session_id"

var webSessionTTL = 12 * time.Hour

type authSession struct {
	username  string
	expiresAt time.Time
}

var authStore = struct {
	sync.Mutex
	sessions map[string]authSession
}{sessions: map[string]authSession{}}

func authEnabled() bool {
	return webUser != "" && webPassword != ""
}

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func createAuthSession(username string) (string, time.Time, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(webSessionTTL)
	authStore.Lock()
	authStore.sessions[token] = authSession{username: username, expiresAt: expiresAt}
	authStore.Unlock()
	return token, expiresAt, nil
}

func validateAuthSession(token string) bool {
	if strings.TrimSpace(token) == "" {
		return false
	}
	now := time.Now()
	authStore.Lock()
	defer authStore.Unlock()
	s, ok := authStore.sessions[token]
	if !ok {
		return false
	}
	if now.After(s.expiresAt) {
		delete(authStore.sessions, token)
		return false
	}
	return true
}

func deleteAuthSession(token string) {
	if token == "" {
		return
	}
	authStore.Lock()
	delete(authStore.sessions, token)
	authStore.Unlock()
}

func setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func isAuthenticated(r *http.Request) bool {
	if !authEnabled() {
		return true
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return validateAuthSession(c.Value)
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if !authEnabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	data, err := staticFiles.ReadFile("login.html")
	if err != nil {
		http.Error(w, "无法加载登录页", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if !authEnabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	secureCookie := r.TLS != nil
	var user, pass string
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType == "application/json" {
		var payload struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "请求格式错误", http.StatusBadRequest)
			return
		}
		user = strings.TrimSpace(payload.Username)
		pass = payload.Password
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "请求参数错误", http.StatusBadRequest)
			return
		}
		user = strings.TrimSpace(r.FormValue("username"))
		pass = r.FormValue("password")
	}

	if user != webUser || pass != webPassword {
		if c, err := r.Cookie(sessionCookieName); err == nil {
			deleteAuthSession(c.Value)
		}
		clearSessionCookie(w, secureCookie)
		if contentType == "application/json" {
			http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/auth/login?error=1", http.StatusFound)
		return
	}

	if c, err := r.Cookie(sessionCookieName); err == nil {
		deleteAuthSession(c.Value)
	}
	token, expiresAt, err := createAuthSession(user)
	if err != nil {
		http.Error(w, "创建登录会话失败", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, token, expiresAt, secureCookie)

	if contentType == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	secureCookie := r.TLS != nil
	if c, err := r.Cookie(sessionCookieName); err == nil {
		deleteAuthSession(c.Value)
	}
	clearSessionCookie(w, secureCookie)
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authEnabled() {
			next(w, r)
			return
		}
		if isAuthenticated(r) {
			next(w, r)
			return
		}

		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.URL.Path == "/ws" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	}
}
