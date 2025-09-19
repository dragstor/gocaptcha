// Package gocaptcha provides invisible + behavioral CAPTCHA protection
// for Go web apps using standard net/http.
package gocaptcha

import (
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	ShowBadge      bool
	BadgeMessage   string
	RateLimitTTL   time.Duration
	RateLimitMax   int
	EnableStorage  bool
	DBPath         string
	BlockThreshold int // Decision threshold (score <= BlockThreshold => block). If 0, defaults to -5 for backward compatibility.

	// Optional bypass controls to exclude certain requests (e.g., OAuth callbacks) from checks.
	SkipPaths []string                   // Any request whose URL.Path has one of these prefixes will bypass checks.
	SkipIf    func(r *http.Request) bool // If provided and returns true, the request bypasses checks.
}

type Captcha struct {
	cfg       Config
	fieldName string
	db        *sql.DB

	rateMu  sync.Mutex
	rateMap map[string][]time.Time // IP -> request timestamps
}

func New(cfg Config) *Captcha {
	// Backward-compatible defaults
	if cfg.RateLimitTTL == 0 {
		cfg.RateLimitTTL = 1 * time.Minute
	}
	if cfg.RateLimitMax == 0 {
		cfg.RateLimitMax = 5
	}
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = -5
	}

	c := &Captcha{
		cfg:       cfg,
		fieldName: "extra_" + randSeq(6),
		rateMap:   make(map[string][]time.Time),
	}
	if cfg.EnableStorage {
		if cfg.DBPath == "" {
			cfg.DBPath = "captcha.db"
		}
		db, err := sql.Open("sqlite3", cfg.DBPath)
		if err == nil {
			c.db = db
			// SQLite-compatible schema with details column for reasons
			c.db.Exec(`CREATE TABLE IF NOT EXISTS captcha_logs (
				id INTEGER PRIMARY KEY,
				ip TEXT,
				ua TEXT,
				score INTEGER,
				details TEXT,
				timestamp TEXT DEFAULT CURRENT_TIMESTAMP
			)`)
			// Keywords and configuration tables
			c.db.Exec(`CREATE TABLE IF NOT EXISTS spam_keywords (id INTEGER PRIMARY KEY, keyword TEXT UNIQUE)`)
			c.db.Exec(`CREATE TABLE IF NOT EXISTS captcha_config (key TEXT PRIMARY KEY, value TEXT)`)
			// Default config: enforce Latin-only text
			c.db.Exec(`INSERT OR IGNORE INTO captcha_config (key, value) VALUES ('latin_only','1')`)
			// Seed default spam keywords (library users can add more later)
			for _, kw := range defaultKeywords() {
				_, _ = c.db.Exec(`INSERT OR IGNORE INTO spam_keywords (keyword) VALUES (?)`, kw)
			}
		}
	}
	return c
}

// Middleware is a wrapper around CheckRequest for basic integration.
func (c *Captcha) Middleware() func(r *http.Request) bool {
	return func(r *http.Request) bool {
		return c.CheckRequest(r)
	}
}

// CheckRequest analyzes the incoming request and returns true if it's likely a bot.
func (c *Captcha) CheckRequest(r *http.Request) bool {
	score := 0
	reasons := []string{}
	if err := r.ParseForm(); err != nil {
		return true // suspicious if malformed form data
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := host
	ua := r.Header.Get("User-Agent")
	ref := r.Header.Get("Referer")
	now := time.Now()

	// Early bypass (OAuth callbacks or configured skips)
	if ok, why := c.shouldBypass(r); ok {
		c.log(ip, ua, 0, []string{why})
		return false
	}

	// 1. Rate limiting
	c.rateMu.Lock()
	hits := c.rateMap[ip]
	var recent []time.Time
	for _, t := range hits {
		if now.Sub(t) < c.cfg.RateLimitTTL {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	c.rateMap[ip] = recent
	c.rateMu.Unlock()
	if len(recent) > c.cfg.RateLimitMax {
		score -= 3
		reasons = append(reasons, "rate_limit_exceeded")
	}

	// 2. Hidden extra field (honeypot)
	if val := strings.TrimSpace(r.FormValue(c.fieldName)); val != "" {
		reasons = append(reasons, "hidden_field_filled")
		c.log(ip, ua, score, reasons)
		return true
	}

	// 2b. Latin-only enforcement (configurable)
	if c.getConfigBool("latin_only", false) {
		if !c.formIsLatinOnly(r) {
			reasons = append(reasons, "non_latin_detected")
			c.log(ip, ua, score, reasons)
			return true
		}
	}

	// 3. Timestamp (client JS writes current time in ms)
	if tsStr := r.FormValue("ts"); tsStr != "" {
		if ts, err := strconv.ParseInt(tsStr, 10, 64); err != nil || now.UnixMilli()-ts < 1500 {
			score -= 3
			reasons = append(reasons, "too_fast_submit")
		}
	} else {
		score -= 3
		reasons = append(reasons, "missing_ts")
	}

	// 4. JS token
	if r.FormValue("js_token") != "set_by_js" {
		score -= 2
		reasons = append(reasons, "missing_js_token")
	}

	// 5. Behavior tracking
	if ok, why := c.checkBehavior(r.FormValue("behavior_data")); !ok {
		score -= 3
		if why != "" {
			reasons = append(reasons, "behavior:"+why)
		} else {
			reasons = append(reasons, "behavior_invalid")
		}
	}

	// 6. UA/Header check
	uaLower := strings.ToLower(ua)
	if ua == "" || !strings.Contains(uaLower, "mozilla") {
		score -= 2
		reasons = append(reasons, "ua_suspicious")
	}
	if ref == "" {
		score -= 1
		reasons = append(reasons, "missing_referer")
	} else if r.Host != "" && !strings.Contains(ref, r.Host) {
		// small penalty if referer is cross-site (embeds/proxies may still be legit)
		score -= 1
		reasons = append(reasons, "cross_site_referer")
	}

	// 7. Headless/User-Agent indicators
	if strings.Contains(ua, "HeadlessChrome") ||
		strings.Contains(ua, "PhantomJS") ||
		strings.Contains(ua, "SlimerJS") ||
		strings.Contains(ua, "Electron") ||
		strings.Contains(ua, "Puppeteer") ||
		ua == "" ||
		strings.Contains(ua, "Go-http-client") ||
		strings.Contains(ua, "curl") ||
		strings.Contains(ua, "python-requests") {
		score -= 4
		reasons = append(reasons, "headless_or_scripted_ua")
	}

	// 7b. Additional header heuristics (lightweight)
	accept := r.Header.Get("Accept")
	al := r.Header.Get("Accept-Language")
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	secFetchMode := r.Header.Get("Sec-Fetch-Mode")
	if accept == "" && al == "" {
		score -= 1
		reasons = append(reasons, "missing_accept_and_language")
	}
	if strings.Contains(uaLower, "chrome") && secFetchSite == "" && secFetchMode == "" {
		// Modern Chromium sends these; missing both is a mild signal
		score -= 1
		reasons = append(reasons, "missing_sec_fetch_headers")
	}

	// 8. JS cookie detection
	jsCookie, err := r.Cookie("js_captcha")
	if errors.Is(http.ErrNoCookie, err) {
		score -= 3
		reasons = append(reasons, "missing_js_cookie")
	} else if err != nil || jsCookie.Value != "enabled" {
		score -= 2
		reasons = append(reasons, "bad_js_cookie")
	}

	// 9. Form content heuristics (names/messages/links)
	if delta, extra := c.analyzeFormContent(r); delta != 0 {
		score += delta // delta is negative for penalties
		reasons = append(reasons, extra...)
	}

	blocked := score <= c.threshold()
	c.log(ip, ua, score, reasons)
	return blocked
}

func (c *Captcha) HoneypotField() string {
	return c.fieldName
}

func (c *Captcha) BadgeHTML() string {
	if !c.cfg.ShowBadge {
		return ""
	}
	msg := c.cfg.BadgeMessage
	if strings.TrimSpace(msg) == "" {
		msg = "Protected by GoCaptcha"
	}
	// Minimal, modern, non-intrusive floating badge with a lock icon
	return `<div style="position:fixed;right:12px;bottom:12px;z-index:2147483647;display:inline-flex;align-items:center;gap:6px;background:rgba(17,17,17,.72);color:#fff;padding:6px 10px;border-radius:999px;backdrop-filter:saturate(150%) blur(6px);box-shadow:0 2px 10px rgba(0,0,0,.2);font:12px/1 system-ui,-apple-system,Segoe UI,Roboto,Arial,Helvetica,sans-serif;">` +
		`<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>` +
		`<span>` + msg + `</span>` +
		`</div>`
}

// threshold returns the configured blocking threshold with backward compatibility.
func (c *Captcha) threshold() int {
	if c.cfg.BlockThreshold == 0 {
		return -5
	}
	return c.cfg.BlockThreshold
}

// log writes a simple log record with reasons if storage is enabled.
func (c *Captcha) log(ip, ua string, score int, reasons []string) {
	if !c.cfg.EnableStorage || c.db == nil {
		return
	}
	b, _ := json.Marshal(reasons)
	_, _ = c.db.Exec(`INSERT INTO captcha_logs (ip, ua, score, details) VALUES (?, ?, ?, ?)`, ip, ua, score, string(b))
}

// checkBehavior validates basic human-like input behavior encoded from the frontend.
// Returns ok flag and optional reason when not ok.
func (c *Captcha) checkBehavior(encoded string) (bool, string) {
	if encoded == "" {
		return false, "missing_behavior"
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		return false, "behavior_decode_error"
	}
	type Event struct {
		X int   `json:"x"`
		Y int   `json:"y"`
		T int64 `json:"t"`
	}
	var events []Event
	if err := json.Unmarshal(decoded, &events); err != nil || len(events) < 5 {
		return false, "behavior_not_enough_events"
	}
	// timestamps must be strictly increasing
	prev := events[0].T
	for _, ev := range events[1:] {
		if ev.T <= prev {
			return false, "behavior_non_monotonic_time"
		}
		prev = ev.T
	}
	// duration should be reasonable (> 600 ms)
	dur := events[len(events)-1].T - events[0].T
	if dur < 600 {
		return false, "behavior_too_short"
	}
	// movement variance: total distance and timing variance
	var totalDist float64
	var deltas []float64
	for i := 1; i < len(events); i++ {
		dx := float64(events[i].X - events[i-1].X)
		dy := float64(events[i].Y - events[i-1].Y)
		dt := float64(events[i].T - events[i-1].T)
		totalDist += math.Hypot(dx, dy)
		deltas = append(deltas, dt)
	}
	if totalDist < 40 { // barely any movement
		return false, "behavior_low_movement"
	}
	// simple coeff of variation for deltas
	var sum, sumsq float64
	for _, d := range deltas {
		sum += d
		sumsq += d * d
	}
	mean := sum / float64(len(deltas))
	if mean > 0 {
		std := math.Sqrt(sumsq/float64(len(deltas)) - mean*mean)
		if std < 10 { // too regular intervals
			return false, "behavior_low_timing_variance"
		}
	}
	return true, ""
}

// analyzeFormContent inspects typical text fields (name, message, etc.) for spammy traits.
// Returns a score delta (negative for penalties) and a list of reasons.
func (c *Captcha) analyzeFormContent(r *http.Request) (int, []string) {
	delta := 0
	reasons := []string{}

	fields := map[string]string{}
	for k := range r.Form {
		v := r.FormValue(k)
		kl := strings.ToLower(k)
		if kl == "name" || kl == "full_name" || kl == "fullname" || kl == "username" {
			fields["name"] = v
		} else if kl == "email" {
			fields["email"] = v
		} else if kl == "website" || kl == "url" || kl == "site" {
			fields["website"] = v
		} else if kl == "message" || kl == "msg" || kl == "comment" || kl == "content" || kl == "bio" || kl == "body" {
			fields["message"] += "\n" + v
		}
	}

	msg := strings.TrimSpace(fields["message"])
	name := strings.TrimSpace(fields["name"])
	email := strings.TrimSpace(fields["email"])
	website := strings.TrimSpace(fields["website"])

	// URLs in message
	urlRe := regexp.MustCompile(`(?i)\b(?:https?://|www\.)\S+`)
	links := urlRe.FindAllString(msg, -1)
	if n := len(links); n > 0 {
		pen := -2 - int(math.Min(float64(n-1), 2)) // -2 first, then -1 up to -4
		delta += pen
		reasons = append(reasons, "links_in_message:"+strconv.Itoa(n))
	}

	// DB-configurable spammy keywords
	kws := c.getSpamKeywords()
	if len(kws) > 0 {
		parts := make([]string, 0, len(kws))
		for _, kw := range kws {
			kw = strings.TrimSpace(kw)
			if kw == "" {
				continue
			}
			parts = append(parts, regexp.QuoteMeta(kw))
		}
		if len(parts) > 0 {
			kwRe := regexp.MustCompile("(?i)(" + strings.Join(parts, "|") + ")")
			if kwRe.MatchString(msg) {
				delta -= 3
				reasons = append(reasons, "spam_keywords")
			}
		}
	}

	// Emoji overuse
	emojiCount := 0
	for _, r := range msg {
		if unicode.Is(unicode.So, r) || (r >= 0x1F300 && r <= 0x1FAFF) {
			emojiCount++
		}
	}
	if emojiCount >= 5 {
		delta -= 1
		reasons = append(reasons, "emoji_overuse:"+strconv.Itoa(emojiCount))
	}
	if emojiCount >= 12 {
		delta -= 1
	}

	// Repeated punctuation: 5+ of the same from [!?*&_-]
	if hasRepeatedPunct(msg) {
		delta -= 1
		reasons = append(reasons, "repeated_punct")
	}

	// Name should not contain URL
	if name != "" && urlRe.MatchString(name) {
		delta -= 2
		reasons = append(reasons, "name_contains_url")
	}
	// Website must look like a URL if provided
	if website != "" && !urlRe.MatchString(website) {
		delta -= 1
		reasons = append(reasons, "website_invalid")
	}

	// Basic email validation
	emailRe := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	if email != "" && !emailRe.MatchString(email) {
		delta -= 1
		reasons = append(reasons, "email_invalid")
	}

	// Very short message with link is suspicious
	if utf8.RuneCountInString(msg) < 15 && len(links) > 0 {
		delta -= 1
		reasons = append(reasons, "short_msg_with_link")
	}

	return delta, reasons
}

// getConfigBool reads a boolean-like configuration value from the DB with a default fallback.
func (c *Captcha) getConfigBool(key string, def bool) bool {
	if c.db == nil {
		return def
	}
	var v string
	err := c.db.QueryRow(`SELECT value FROM captcha_config WHERE key = ?`, key).Scan(&v)
	if err != nil {
		return def
	}
	s := strings.TrimSpace(strings.ToLower(v))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}

// defaultKeywords returns a seed list of common spammy tokens/phrases.
func defaultKeywords() []string {
	return []string{
		"earn", "money", "cash", "crypto", "bitcoin", "forex", "seo", "backlink", "guest post",
		"sponsor", "telegram", "whatsapp", "casino", "bet", "loan", "payday", "work from home",
		"adult", "porn", "viagra", "sex", "xxx", "escort", "nft", "investment", "binary options",
		"cheap", "discount", "limited offer", "promo", "marketing", "followers", "likes",
	}
}

// getSpamKeywords returns the keywords from DB if available, otherwise seeds.
func (c *Captcha) getSpamKeywords() []string {
	if c.db == nil {
		return defaultKeywords()
	}
	rows, err := c.db.Query(`SELECT keyword FROM spam_keywords`)
	if err != nil {
		return defaultKeywords()
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var kw string
		if err := rows.Scan(&kw); err == nil {
			out = append(out, kw)
		}
	}
	if len(out) == 0 {
		return defaultKeywords()
	}
	return out
}

// isLatinOnlyText returns false if the string contains any Letter/Mark not in the Latin unicode script.
func isLatinOnlyText(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsMark(r) {
			if !unicode.Is(unicode.Latin, r) {
				return false
			}
		}
	}
	return true
}

// formIsLatinOnly validates all form values (excluding the hidden extra field) for Latin-only letters.
func (c *Captcha) formIsLatinOnly(r *http.Request) bool {
	for k, vals := range r.Form {
		if k == c.fieldName {
			continue
		}
		for _, v := range vals {
			if !isLatinOnlyText(v) {
				return false
			}
		}
	}
	return true
}

func randSeq(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

// shouldBypass returns true and a reason if the request should bypass CAPTCHA checks (e.g., OAuth callbacks).
func (c *Captcha) shouldBypass(r *http.Request) (bool, string) {
	// Custom predicate provided by integrator
	if c.cfg.SkipIf != nil {
		defer func() { _ = recover() }() // guard against panics in user callback
		if c.cfg.SkipIf(r) {
			return true, "bypass:custom"
		}
	}
	// Path-based bypass (prefix match)
	if len(c.cfg.SkipPaths) > 0 {
		p := r.URL.Path
		for _, pref := range c.cfg.SkipPaths {
			if pref == "" {
				continue
			}
			if strings.HasPrefix(p, pref) {
				return true, "bypass:skip_path"
			}
		}
	}
	// Heuristic OAuth2 callback detection: typical provider redirect back
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		code := strings.TrimSpace(q.Get("code"))
		state := strings.TrimSpace(q.Get("state"))
		pathLower := strings.ToLower(r.URL.Path)
		ref := strings.ToLower(r.Header.Get("Referer"))
		if code != "" && state != "" {
			return true, "bypass:oauth_flow"
		}
		if (strings.Contains(pathLower, "/oauth") || strings.Contains(pathLower, "/oauth2") || strings.Contains(pathLower, "/auth/") || strings.HasSuffix(pathLower, "/callback")) && (code != "" || state != "") {
			return true, "bypass:oauth_flow"
		}
		if strings.Contains(ref, "accounts.google.com") || strings.Contains(ref, "github.com/login") || strings.Contains(ref, "github.com/session") {
			return true, "bypass:oauth_referer"
		}
	}
	return false, ""
}

// Stats structs and helper methods

// StatIP represents an IP with its occurrence count in logs.
type StatIP struct {
	IP    string
	Count int
}

// StatUA represents a User-Agent with its occurrence count in logs.
type StatUA struct {
	UserAgent string
	Count     int
}

// StatHour represents an hour-of-day (0-23) with a count.
type StatHour struct {
	Hour  int
	Count int
}

// StatReason represents a block reason with its occurrence count.
type StatReason struct {
	Reason string
	Count  int
}

// TopIPs returns the most frequent IPs seen in captcha_logs.
// If spamOnly is true, it filters to rows where score <= current threshold.
// If limit <= 0, a default of 10 is used.
func (c *Captcha) TopIPs(limit int, spamOnly bool) ([]StatIP, error) {
	if c.db == nil {
		return nil, errors.New("storage not enabled")
	}
	if limit <= 0 {
		limit = 10
	}
	var (
		rows *sql.Rows
		err  error
	)
	if spamOnly {
		rows, err = c.db.Query(`SELECT ip, COUNT(*) AS cnt FROM captcha_logs WHERE ip <> '' AND score <= ? GROUP BY ip ORDER BY cnt DESC LIMIT ?`, c.threshold(), limit)
	} else {
		rows, err = c.db.Query(`SELECT ip, COUNT(*) AS cnt FROM captcha_logs WHERE ip <> '' GROUP BY ip ORDER BY cnt DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StatIP{}
	for rows.Next() {
		var ip string
		var cnt int
		if err := rows.Scan(&ip, &cnt); err != nil {
			return nil, err
		}
		out = append(out, StatIP{IP: ip, Count: cnt})
	}
	return out, rows.Err()
}

// TopUserAgents returns the most frequent User-Agents seen in captcha_logs.
// If spamOnly is true, only entries with score <= current threshold are included.
func (c *Captcha) TopUserAgents(limit int, spamOnly bool) ([]StatUA, error) {
	if c.db == nil {
		return nil, errors.New("storage not enabled")
	}
	if limit <= 0 {
		limit = 10
	}
	var (
		rows *sql.Rows
		err  error
	)
	if spamOnly {
		rows, err = c.db.Query(`SELECT ua, COUNT(*) AS cnt FROM captcha_logs WHERE ua <> '' AND score <= ? GROUP BY ua ORDER BY cnt DESC LIMIT ?`, c.threshold(), limit)
	} else {
		rows, err = c.db.Query(`SELECT ua, COUNT(*) AS cnt FROM captcha_logs WHERE ua <> '' GROUP BY ua ORDER BY cnt DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StatUA{}
	for rows.Next() {
		var ua string
		var cnt int
		if err := rows.Scan(&ua, &cnt); err != nil {
			return nil, err
		}
		out = append(out, StatUA{UserAgent: ua, Count: cnt})
	}
	return out, rows.Err()
}

// TopHours returns the hours of day with the most activity.
// If spamOnly is true, only entries with score <= current threshold are included.
func (c *Captcha) TopHours(limit int, spamOnly bool) ([]StatHour, error) {
	if c.db == nil {
		return nil, errors.New("storage not enabled")
	}
	if limit <= 0 {
		limit = 5
	}
	var (
		rows *sql.Rows
		err  error
	)
	if spamOnly {
		rows, err = c.db.Query(`SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS h, COUNT(*) AS cnt FROM captcha_logs WHERE score <= ? GROUP BY h ORDER BY cnt DESC LIMIT ?`, c.threshold(), limit)
	} else {
		rows, err = c.db.Query(`SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS h, COUNT(*) AS cnt FROM captcha_logs GROUP BY h ORDER BY cnt DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StatHour{}
	for rows.Next() {
		var h int
		var cnt int
		if err := rows.Scan(&h, &cnt); err != nil {
			return nil, err
		}
		out = append(out, StatHour{Hour: h, Count: cnt})
	}
	return out, rows.Err()
}

// HourlyCounts returns a 24-length slice with counts per hour (0..23).
// If spamOnly is true, only entries with score <= current threshold are included.
func (c *Captcha) HourlyCounts(spamOnly bool) ([]int, error) {
	if c.db == nil {
		return nil, errors.New("storage not enabled")
	}
	counts := make([]int, 24)
	var (
		rows *sql.Rows
		err  error
	)
	if spamOnly {
		rows, err = c.db.Query(`SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS h, COUNT(*) AS cnt FROM captcha_logs WHERE score <= ? GROUP BY h`, c.threshold())
	} else {
		rows, err = c.db.Query(`SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS h, COUNT(*) AS cnt FROM captcha_logs GROUP BY h`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h int
		var cnt int
		if err := rows.Scan(&h, &cnt); err != nil {
			return nil, err
		}
		if h >= 0 && h < 24 {
			counts[h] = cnt
		}
	}
	return counts, rows.Err()
}

// TopReasons returns the most frequent reasons recorded in details JSON.
// If spamOnly is true, it filters to rows where score <= current threshold.
func (c *Captcha) TopReasons(limit int, spamOnly bool) ([]StatReason, error) {
	if c.db == nil {
		return nil, errors.New("storage not enabled")
	}
	if limit <= 0 {
		limit = 10
	}
	var (
		rows *sql.Rows
		err  error
	)
	if spamOnly {
		rows, err = c.db.Query(`SELECT details FROM captcha_logs WHERE score <= ?`, c.threshold())
	} else {
		rows, err = c.db.Query(`SELECT details FROM captcha_logs`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	freq := make(map[string]int)
	for rows.Next() {
		var details string
		if err := rows.Scan(&details); err != nil {
			return nil, err
		}
		var reasons []string
		if err := json.Unmarshal([]byte(details), &reasons); err != nil {
			continue
		}
		for _, r := range reasons {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			freq[r]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	arr := make([]StatReason, 0, len(freq))
	for k, v := range freq {
		arr = append(arr, StatReason{Reason: k, Count: v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Count == arr[j].Count {
			return arr[i].Reason < arr[j].Reason
		}
		return arr[i].Count > arr[j].Count
	})
	if len(arr) > limit {
		arr = arr[:limit]
	}
	return arr, nil
}

// hasRepeatedPunct reports whether the string contains 5 or more of the same
// punctuation character from the set [!?*&_-] in a row.
func hasRepeatedPunct(s string) bool {
	var prev rune
	count := 0 // number of repeats of prev (consecutive minus one)
	hasPrev := false
	for _, r := range s {
		if hasPrev && r == prev && isSpecialPunct(r) {
			count++
			if count >= 4 { // 1 + 4 = 5 identical in a row
				return true
			}
		} else {
			count = 0
		}
		prev = r
		hasPrev = true
	}
	return false
}

func isSpecialPunct(r rune) bool {
	switch r {
	case '!', '?', '*', '&', '_', '-':
		return true
	default:
		return false
	}
}

// Embedded JS file and helpers to serve it without copying files into your app.
//
//go:embed static/js/gocaptcha.js
var embeddedJS embed.FS

// JSHandler returns an http.Handler that serves the embedded GoCaptcha JS file.
// Mount it under a URL prefix (usually "/static/js/") so that
//
//	/static/js/gocaptcha.js
//
// is reachable by the browser.
func JSHandler() http.Handler {
	sub, err := fs.Sub(embeddedJS, "static/js")
	if err != nil {
		// Should never happen; return a simple 500 handler if it does.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "GoCaptcha JS not available", http.StatusInternalServerError)
		})
	}
	return http.FileServer(http.FS(sub))
}

// JSHandlerWithPrefix wraps JSHandler with http.StripPrefix for easier mounting.
// Example (net/http):
//
//	http.Handle("/static/js/", gocaptcha.JSHandlerWithPrefix("/static/js/"))
//
// Example (Gin):
//
//	r.Any("/static/js/*filepath", gin.WrapH(gocaptcha.JSHandlerWithPrefix("/static/js/")))
func JSHandlerWithPrefix(prefix string) http.Handler {
	p := strings.TrimRight(prefix, "/") + "/"
	return http.StripPrefix(p, JSHandler())
}
