# 🛡️ GoCaptcha

Invisible + behavioral CAPTCHA for Go net/http apps (<del>works</del> Should work with any router, optional Gin usage).
It’s silent-by-default, adding small penalties for bot-like signals and hard-blocking only when the score crosses a
configurable threshold.

Badge preview (default style and text):

![Badge example](badge-example.png)

## Highlights

- Randomized hidden field (not named "honeypot")
- Timestamp + JS token + behavior tracking
- JS cookie check (js_captcha=enabled)
- Header/UA heuristics (detect headless/scripted clients)
- Per‑IP rate limiting
- SQLite logging with JSON reasons (for tuning and audits)
- Seeded spam keyword table + configurable Latin‑only enforcement
- OAuth callback bypass support (SkipPaths, SkipIf)
- Stats helpers (TopIPs, TopUserAgents, TopHours, HourlyCounts, TopReasons)
- Optional floating badge with lock icon

---

## Install

```bash
go get github.com/dragstor/gocaptcha
```

Import:

```go
import (
    "net/http"
    "time"

    "github.com/dragstor/gocaptcha"
)
```

## Go version support

- Minimum supported Go version: 1.20. The module's `go` directive is set to 1.20 to maximize compatibility while staying modern.
- Rationale: libraries should pin the minimum version they require, not the latest. This avoids breaking users on slightly older toolchains while still allowing everyone on newer Go versions to build and run.

---

## Quick start (net/http)

```go
cap := gocaptcha.New(gocaptcha.Config{
    ShowBadge:      true,                     // show small lock badge (optional)
    BadgeMessage:   "Protected by GoCaptcha", // badge text
    RateLimitTTL:   time.Minute,              // per-IP window
    RateLimitMax:   10,                       // max requests/window
    EnableStorage:  true,                     // enable SQLite logs + seeding
    DBPath:         "./captcha.db",           // defaults to ./captcha.db if empty
    BlockThreshold: -5,                       // block when score <= threshold
    // Bypass OAuth callbacks:
    SkipPaths: []string{"/auth/", "/oauth2/"},
    // Or a custom predicate:
    // SkipIf: func(r *http.Request) bool { return detectMyOauthCallback(r) },
})

http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        if cap.CheckRequest(r) {
            // Prefer "pretend success" to avoid leaking detection to bots.
            http.Redirect(w, r, "/thanks", http.StatusSeeOther)
            return
        }
        // Handle real registration here…
        w.Write([]byte("ok"))
        return
    }

    // Render the form (example uses raw HTML; templates recommended)
    honeypot := cap.HoneypotField()
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write([]byte(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Register</title>
</head>
<body>
  <form method="POST">
    <input type="hidden" name="ts" id="ts" />
    <input type="hidden" name="js_token" id="js_token" />
    <input type="hidden" name="behavior_data" id="behavior_data" />
    <input type="text" name="` + honeypot + `" style="display:none" tabindex="-1" autocomplete="off" aria-hidden="true" />

    <input type="text" name="name" placeholder="Your name" />
    <input type="email" name="email" placeholder="you@example.com" />
    <textarea name="message" placeholder="Message"></textarea>
    <button type="submit">Submit</button>
  </form>
  <script src="/static/js/gocaptcha.js"></script>
  ` + cap.BadgeHTML() + `
</body>
</html>`))
})

http.ListenAndServe(":8080", nil)
```

Serve the JS file at /static/js/gocaptcha.js (see Frontend section).

---

## Gin usage (with templates or inline HTML)

GoCaptcha works with Gin by calling CheckRequest on POST. Important: the library does not and cannot inject HTML.
You must render the hidden inputs (or let the JS create them), include the JS file, and include the badge HTML
in your GET page/template.

```go
r := gin.Default()
cap := gocaptcha.New(gocaptcha.Config{
    ShowBadge:    true,
    BadgeMessage: "Protected by GoCaptcha",
    // ... other config
})

r.GET("/register", func(c *gin.Context) {
    honeypot := cap.HoneypotField()
    c.Header("Content-Type", "text/html; charset=utf-8")
    c.String(http.StatusOK, `<!doctype html>
<html>
<body>
  <form method="POST">
    <input type="hidden" name="ts" id="ts" />
    <input type="hidden" name="js_token" id="js_token" />
    <input type="hidden" name="behavior_data" id="behavior_data" />
    <input type="text" name="` + honeypot + `" style="display:none" tabindex="-1" autocomplete="off" aria-hidden="true" />
    <input type="text" name="name" placeholder="Your name" />
    <button type="submit">Submit</button>
  </form>
  <script src="/static/js/gocaptcha.js"></script>
  ` + cap.BadgeHTML() + `
</body>
</html>`)
})

r.POST("/register", func(c *gin.Context) {
    if cap.CheckRequest(c.Request) {
        c.Redirect(http.StatusSeeOther, "/thanks")
        return
    }
    c.String(http.StatusOK, "ok")
})
```

Note: cap.Middleware() returns a simple func(*http.Request) bool helper; call CheckRequest in your handlers as above.

---

## Frontend (static/js/gocaptcha.js)

Use the provided minimal script. It populates ts, js_token, behavior_data and sets the js_captcha cookie.

```html
<script src="/static/js/gocaptcha.js"></script>
```

File contents (already included in this repo at static/js/gocaptcha.js):

```js
(function () {
    // Always set the cookie to signal JS is enabled (even if form fields are missing)
    try {
        document.cookie = "js_captcha=enabled; Max-Age=31536000; Path=/; SameSite=Lax";
    } catch (e) {}

    // Helper to ensure a hidden input exists in a given form
    function ensureHidden(form, id) {
        let el = form.querySelector('#' + id);
        if (!el) {
            el = document.createElement('input');
            el.type = 'hidden';
            el.name = id;
            el.id = id;
            form.appendChild(el);
        }
        return el;
    }

    const forms = Array.from(document.querySelectorAll('form'));
    if (forms.length === 0) return;

    // Shared behavior events buffer
    const events = [];
    document.addEventListener('mousemove', e => {
        events.push({x: e.clientX, y: e.clientY, t: Date.now()});
    });
    document.addEventListener('keydown', () => {
        events.push({key: true, t: Date.now()});
    });
    document.addEventListener('click', () => {
        events.push({click: true, t: Date.now()});
    });

    // Initialize and wire up each form
    forms.forEach(form => {
        const tsField = ensureHidden(form, 'ts');
        const jsToken = ensureHidden(form, 'js_token');
        const behaviorField = ensureHidden(form, 'behavior_data');

        tsField.value = Date.now().toString();
        jsToken.value = 'set_by_js';

        form.addEventListener('submit', () => {
            try {
                behaviorField.value = btoa(JSON.stringify(events.slice(0, 100)));
            } catch (err) {}
        });
    });
})();
```

Note: Legacy files gocaptcha.js and js/gocaptcha.js are deprecated stubs. Use static/js/gocaptcha.js.

## Serving the JS file (Gin and net/http)

There are two ways to make the browser load the script:

- Option A — copy the file into your app’s public static directory and serve it as you already do. The file you need is at static/js/gocaptcha.js in this module.
- Option B — mount the embedded handler provided by this library (no copying required).

net/http:

```go
http.Handle("/static/js/", gocaptcha.JSHandlerWithPrefix("/static/js/"))
// then in your HTML: <script src="/static/js/gocaptcha.js"></script>
```

Gin:

```go
r.Any("/static/js/*filepath", gin.WrapH(gocaptcha.JSHandlerWithPrefix("/static/js/")))
// optionally also add HEAD if you prefer separate routes
```

This simply serves the single file gocaptcha.js at the path /static/js/gocaptcha.js.

---

## Troubleshooting

- Badge not visible on your form even with ShowBadge = true:
  You must actually render the returned HTML by calling cap.BadgeHTML() in your page/template. Middleware cannot
  inject markup into your responses. Add something like: ` + "`" + `{{.CaptchaBadgeHTML}}` + "`" + ` (template) or concatenate
  ` + "`" + `cap.BadgeHTML()` + "`" + ` into your HTML string.

- Immediate redirects and logs show ["missing_ts","missing_js_token","behavior:missing_behavior","missing_js_cookie"]:
  This means the frontend integration is missing. Ensure that:
  - Your GET page includes <script src="/static/js/gocaptcha.js"></script> just before </body>.
  - Your form has hidden fields with ids ts, js_token, behavior_data (the script now auto-creates them if missing).
  - Cookies are allowed (js_captcha=enabled). If you’re testing on a very strict browser profile or with blocked cookies,
    the cookie check will add penalties.

- Using Gin or other routers:
  The middleware/helper only checks requests; it does not render the HTML. Add the script and badge HTML yourself in the
  GET handler or template as shown in the examples above.

---

## Configuration reference

Config fields (gocaptcha.Config):

- ShowBadge bool — render a floating badge via BadgeHTML()
- BadgeMessage string — text inside the badge
- RateLimitTTL time.Duration — per-IP window for rate limiting
- RateLimitMax int — max requests in the window before a small penalty
- EnableStorage bool — enable SQLite logs and automatic seeding
- DBPath string — path to SQLite db (defaults to captcha.db when empty)
- BlockThreshold int — block if score <= threshold (default -5)
- SkipPaths []string — path prefixes to bypass checks (e.g., "/auth/", "/oauth2/")
- SkipIf func(*http.Request) bool — custom bypass logic (e.g., OAuth callback detection)

Behavior overview:

- Hidden field: name returned by HoneypotField(); if filled, immediate block.
- Latin-only: when enabled (default), any non‑Latin letters in submitted text cause a hard block.
- JS/Timing: missing ts/js_token/behavior_data or too-fast submit penalized.
- Cookies/Headers: missing js_captcha cookie, suspicious UA, or missing headers add mild penalties.
- Content heuristics: URLs, spam keywords, emoji overuse, repeated punctuation, invalid email/URL, etc.

---

## Storage, seeding, and configuration (SQLite)

When EnableStorage is true, the library will create the database (if needed) and ensure these tables exist:

- captcha_logs(id, ip, ua, score, details JSON, timestamp)
- spam_keywords(id, keyword UNIQUE)
- captcha_config(key PRIMARY KEY, value)

Seeded defaults:

- captcha_config: latin_only = 1 (enabled)
- spam_keywords: a baseline set (e.g., earn, money, cash, crypto, bitcoin, forex, seo, backlink, guest post, sponsor,
  telegram, whatsapp, casino, bet, loan, payday, work from home, adult, porn, viagra, sex, xxx, escort, nft, investment,
  binary options, cheap, discount, limited offer, promo, marketing, followers, likes)

Change configuration:

```sql
-- Disable Latin-only enforcement
UPDATE captcha_config
SET value='0'
WHERE key = 'latin_only';
-- Or enable it again
UPDATE captcha_config
SET value='1'
WHERE key = 'latin_only';
```

Add your own spam keywords:

```sql
INSERT OR IGNORE INTO spam_keywords(keyword)
VALUES ('a new scam'),
       ('free crypto'),
       ('backlink offer');
```

Note: If you previously created captcha_logs with a different schema, you may need to recreate it to include the details
column.

---

## Bypassing OAuth callbacks

To ensure OAuth logins (Google/GitHub/etc.) aren’t blocked, configure bypasses:

```go
cap := gocaptcha.New(gocaptcha.Config{
    SkipPaths: []string{"/auth/", "/oauth2/"},
    // Or provide SkipIf to detect your exact callback shape
    SkipIf: func(r *http.Request) bool {
        q := r.URL.Query()
        return r.Method == http.MethodGet && q.Get("code") != "" && q.Get("state") != ""
    },
})
```

The library also includes heuristics to auto-bypass common OAuth callback patterns.

---

## Stats helpers

Use these helpers to analyze trends from captcha_logs (storage must be enabled):

```go
ips, _ := cap.TopIPs(10, true) // top IPs among blocked entries
uas, _ := cap.TopUserAgents(10, true) // top UAs among blocked entries
hours, _ := cap.TopHours(5, true) // busiest spam hours
arr, _ := cap.HourlyCounts(true) // 24-length array of counts per hour
reasons, _ := cap.TopReasons(10, true) // most frequent reasons
```

---

## Tuning tips

- Start with BlockThreshold = -5. If strong signals still pass, try -4; if false positives appear, try -6.
- Keep content penalties low; rely on strong technical signals (JS, cookie, headers, behavior).
- Prefer redirecting to a generic “Thanks” page even when blocked (pretend success). This avoids spammer feedback loops.
- Review logs and TopReasons to refine spam_keywords and weights.

---

## License

MIT
