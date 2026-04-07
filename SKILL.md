---
name: vibecoding-security
description: Use this skill when building, reviewing, or shipping any web app or vibe coding project (Next.js, Supabase, AI apps). Triggers include: "is my app secure", "security check", "before I ship", "review my project", any new project setup, or when adding auth/API/database features. Also triggers automatically when writing API routes, handling user input, setting up Supabase tables, or integrating AI APIs.
---

# Vibecoding Security Skill

## Overview

AI will help you ship fast. It will NOT warn you when your app is a security disaster.
That's on you — and on this skill.

**Core principle:** Security is not a feature you add at the end. Every API route, every user input, every database table is a potential attack surface.

---

## The Iron Law

```
NEVER SHIP WITHOUT RUNNING THE SECURITY CHECKLIST
```

Before any production deploy, run through all 6 areas below. No exceptions.

---

## 1. API Keys — Never Exposed

### The Risk
API keys are the passwords your app uses to talk to other services. Leave them exposed and someone else uses them — on your bill. Bots scan GitHub repos in real time, right now.

### Mandatory Rules

**Storage:**
- ALL keys go in `.env.local` (Next.js) or `.env` (Python/other)
- `.env*` files MUST be in `.gitignore` — verify for BOTH backend and frontend folders separately
- Never hardcode a key in any file that gets committed to git
- `.env.example` files must use placeholder values only — never real IDs or keys, even non-secret ones

**Architecture:**
- API calls to Anthropic, Supabase, or any external service → server-side only
- In Next.js: use API Routes (`/app/api/`) or Server Actions
- Never call external APIs from Client Components or browser-side code
- `NEXT_PUBLIC_` prefix = visible to browser → NEVER use for secrets
- Supabase Anon key → safe for client-side (designed for this)
- Supabase Service Role key → only server-side, never in browser

**Git History Check (run on every existing project):**
```bash
# Check if keys were ever committed
git log --all --full-history -p -- .env
git log --all --full-history -p -- .env.local

# Check .env is not currently tracked
git ls-files | grep ".env"

# Verify .gitignore covers both backend and frontend
cat .gitignore | grep ".env"
cat frontend/.gitignore | grep ".env"
```

**If a key was exposed:**
1. Rotate it immediately in the provider dashboard (Anthropic, Supabase, Stripe, etc.)
2. Clean git history: `git filter-branch` or BFG Repo Cleaner
3. Force-push the cleaned history

**Quick grep to find hardcoded secrets:**
```bash
grep -r "sk-ant" src/            # Anthropic keys
grep -r "SUPABASE_SERVICE" src/  # Supabase service role
grep -r "process.env" src/app --include="*.tsx" | grep -v "server"
```

---

## 2. Rate Limiting — Every Public Endpoint

### The Risk
Without rate limiting, one bot can drain your server and your bank account. AI endpoints are especially dangerous — every request costs real money. Business-logic limits (e.g. "10 posts per day per user") are NOT a substitute — they protect against legitimate overuse, not against bots or parallel request attacks.

### Mandatory Rules

**For FastAPI/Python projects — use slowapi:**
```python
# rate_limit.py — separate module to avoid circular imports
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import base64, json

limiter = Limiter(key_func=get_remote_address)

def _user_key_func(request) -> str:
    """Extract user ID (sub claim) from JWT for per-user rate limiting.
    Falls back to IP if token is missing or malformed.
    Never use raw token as key — tokens rotate and reset the counter."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        try:
            payload = auth[7:].split(".")[1]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload))
            return data.get("sub", get_remote_address(request))
        except Exception:
            pass
    return get_remote_address(request)

# In main.py:
# app.state.limiter = limiter
# app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

**For Next.js/serverless — use Upstash:**
```typescript
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, "1 m"),
});

const identifier = req.ip ?? "anonymous";
const { success } = await ratelimit.limit(identifier);
if (!success) return Response.json({ error: "Too many requests" }, { status: 429 });
```

**Limits by endpoint type:**
| Endpoint Type | Recommended Limit | Key |
|---|---|---|
| AI/LLM endpoints | 5-10 req/min | per User |
| Login/Auth endpoints | 5 req/min | per IP |
| Public endpoints (no auth) | 3-5 req/min | per IP |
| Feedback / email-sending | 2 req/min | per User |
| Destructive actions (DELETE account) | 1 req/5min | per User |
| Stripe API endpoints | 10 req/min | per User |
| General authenticated endpoints | 30-60 req/min | per User |

**Important — per-User vs per-IP:**
- Authenticated endpoints → use User ID as key (not IP — users behind NAT share IPs)
- Public endpoints without auth → use IP
- Never use raw JWT token as rate limit key — tokens rotate and reset the counter

**Middleware order matters (FastAPI):**
- Add SlowAPI middleware AFTER CORSMiddleware (middleware stack is LIFO)

---

## 3. Race Conditions — Counter-Before-Call Pattern

### The Risk
This is the hidden danger in AI apps that nobody talks about. If you check a usage limit, then make the API call, then increment the counter — a user can fire 20 parallel requests simultaneously. All pass the limit check (they all see the same counter value), all trigger API calls, and only then do the counters increment. Result: 20 Claude API calls instead of 1.

**This is distinct from rate limiting** — rate limiting protects against bots, this protects against a single authenticated user exploiting timing.

### Mandatory Pattern: Increment Before, Rollback on Failure

```python
# WRONG — check then act (race condition)
slot_info = get_slot_info(user_id)           # check
if slot_info.used >= slot_info.limit:
    raise HTTPException(429)
result = await call_anthropic(prompt)         # API call
increment_slot_counter(user_id)              # increment AFTER — too late

# RIGHT — increment first, rollback on failure
check_and_increment_slot(user_id)            # increment immediately, 429 if at limit
try:
    result = await call_anthropic(prompt)    # API call
except Exception:
    decrement_slot_counter(user_id)          # rollback on failure
    raise
```

**Rules:**
- Always increment usage counters BEFORE the expensive API call
- Wrap the API call in try/except — decrement on any failure
- Apply this pattern to: Anthropic calls, image generation, email sends, Stripe charges
- Provide separate `_decrement_*` helper functions for clean rollback

---

## 4. Input Sanitization — Trust Nothing

### The Risk
Every text box in your app is a potential attack surface. SQL injection, XSS, prompt injection, and token-overflow attacks all start with unchecked user input.

**For AI apps: Prompt Injection is the new SQL injection.** Users can try to override your system prompt, extract your instructions, or manipulate AI behavior.

### Mandatory Rules

**Server-side validation — Python (Pydantic):**
```python
from pydantic import BaseModel, Field

class GeneratePostRequest(BaseModel):
    input_text: str = Field(min_length=1, max_length=5000)
    custom_prompt: str | None = Field(default=None, max_length=2000)

class UserProfileRequest(BaseModel):
    first_name: str = Field(min_length=1, max_length=50)
    telegram_id: str = Field(pattern=r'^\d{5,15}$')
```

**Server-side validation — TypeScript (Zod):**
```typescript
import { z } from "zod";

const MessageSchema = z.object({
  message: z.string().min(1).max(2000),
  userId: z.string().uuid(),
});
```

**Max-length reference by field type:**
| Field Type | Recommended Max |
|---|---|
| Names, labels, categories | 50-100 chars |
| Short messages, titles | 500-1000 chars |
| Long messages, feedback | 5000 chars |
| AI input text | 5000 chars |
| Custom system prompts | 2000 chars |
| Generated content (posts, etc.) | 15000 chars |
| URLs | 500 chars |
| Numeric IDs (e.g. Telegram) | Regex pattern, not just length |
| List fields (e.g. slides, tags) | Max item count + max per item |

**XSS — dangerouslySetInnerHTML:**
```typescript
// NEVER do this with user content or AI-generated HTML:
<div dangerouslySetInnerHTML={{ __html: content }} />

// ALWAYS sanitize first:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />
```

**XSS — server-side HTML rendering (Python):**
```python
import html

# Never interpolate external data into HTML directly:
return f"<p>Welcome to {workspace_name}</p>"         # WRONG

# Always escape:
return f"<p>Welcome to {html.escape(workspace_name)}</p>"  # RIGHT
```

**Prompt Injection Protection:**
```python
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},      # never mix with user input
    {"role": "user", "content": validated_user_input},  # validated + length-limited
]
```

**Rules:**
- Validate server-side ALWAYS — browser/frontend validation is cosmetic only
- Never build database queries by concatenating strings
- Set max_length on every Pydantic/Zod field that accepts user input — no exceptions
- Use regex validation for fields with known formats (IDs, phone numbers, etc.)
- Sanitize HTML with DOMPurify on every `dangerouslySetInnerHTML` call
- Use `html.escape()` on any external string interpolated into server-rendered HTML

---

## 5. Row Level Security (RLS) — Database as Last Defense

### The Risk
Without RLS, every logged-in user can read everyone else's data. A user could also edit their own pricing tier or permissions directly. This has happened to real products.

**Important:** Even if your frontend never queries Supabase directly, the Supabase Anon key is publicly visible in your frontend code. Anyone can use it to query PostgREST directly — bypassing your backend entirely. RLS is the last line of defense.

### The Privilege Escalation Trap (very common mistake)

This is the most dangerous RLS mistake and it's easy to miss. The standard Supabase pattern allows users to update their own row:

```sql
-- DANGEROUS if plan/permissions are in the same table
CREATE POLICY "users_update_own" ON users FOR UPDATE
  USING (auth.uid() = user_id);
```

If your `users` table contains both profile data AND privilege columns, a user can update their own privileges directly via PostgREST:

```javascript
// User opens DevTools and runs this in the browser console:
await supabase.from('users')
  .update({ plan: 'pro', is_admin: true, post_limit: 99999 })
  .eq('user_id', 'my-own-id')
// → succeeds if UPDATE policy exists on the table
```

**The fix — two options:**

Option A: Separate privilege columns into a backend-only table with deny_anon policy. Users can update their profile table, but never the privileges table.

Option B: Use a full deny model — no direct client access to any table, all mutations go through your backend API with server-side authorization checks.

```sql
-- Option B: Full deny model (most secure)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_all_client_access" ON users
  FOR ALL TO anon, authenticated USING (false);
-- Backend uses service_role key which bypasses RLS entirely
```

**Columns that must NEVER be user-writable:**
- `plan`, `subscription_tier`, `is_pro`, `is_admin`
- `post_limit`, `daily_limit`, `monthly_limit` (any usage cap)
- `ever_paid`, `is_free_member` (feature gating flags)
- `credits`, `tokens`, `balance` (any currency/quota)
- `role`, `permissions` (any access control field)

### Mandatory Rules

**Two policy patterns — pick the right one:**

```sql
-- Pattern 1: User owns their data (standard — safe only if privileges are separate)
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_read_own" ON user_profiles FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY "users_insert_own" ON user_profiles FOR INSERT
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY "users_update_own" ON user_profiles FOR UPDATE
  USING (auth.uid() = user_id);
CREATE POLICY "users_delete_own" ON user_profiles FOR DELETE
  USING (auth.uid() = user_id);

-- Pattern 2: Full deny — backend-only access via service_role
ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_all_client" ON your_table
  FOR ALL TO anon, authenticated USING (false);
```

**Use Pattern 2 (full deny) when:**
- Your backend uses service_role to access the table
- The table contains any privilege, plan, limit, or permission columns
- The table should never be directly queryable from the browser

**Always write explicit policies** — don't rely on implicit deny. Supabase's behavior could change, and implicit deny gives no audit trail.

**Testing RLS (mandatory before ship):**
1. Create a second Supabase auth account
2. Log in as User B
3. Attempt to read, modify, or delete User A's data via PostgREST directly
4. Attempt to update your own `plan`, `is_admin`, or limit columns via PostgREST
5. Every attempt must fail with a permission error

---

## 6. Auth & Middleware — Performance and Security

### Auth Token Caching

Every request that validates a token with Supabase makes an HTTP call. At scale this creates latency and can hit Supabase rate limits.

```python
import hashlib, time

_token_cache: dict[str, tuple[dict, float]] = {}
CACHE_TTL = 60  # seconds

def get_cached_user(token: str) -> dict | None:
    key = hashlib.sha256(token.encode()).hexdigest()  # never store raw token
    if key in _token_cache:
        user, timestamp = _token_cache[key]
        if time.time() - timestamp < CACHE_TTL:
            return user
        del _token_cache[key]
    return None

def cache_user(token: str, user: dict):
    key = hashlib.sha256(token.encode()).hexdigest()
    _token_cache[key] = (user, time.time())
```

**Rules:**
- Cache validated tokens with 60s TTL
- Use SHA256 hash as cache key — never store the raw token in memory
- Only cache successful validations — never cache 401 errors
- Clean up expired entries on cache miss (lazy cleanup)

---

## Pre-Ship Security Checklist

### API Keys
- [ ] No API keys in any `.js`, `.ts`, `.tsx`, `.jsx`, `.py` files
- [ ] `.env` / `.env.local` in `.gitignore` for ALL project folders
- [ ] `git ls-files | grep ".env"` returns nothing
- [ ] `.env.example` contains only placeholder values
- [ ] All external API calls happen in server-side code only

### Rate Limiting
- [ ] Rate limiting installed (slowapi for Python, Upstash for Next.js)
- [ ] Every public endpoint has a limit
- [ ] AI/LLM endpoints: strict limits (cost protection)
- [ ] Auth endpoints: strict limits (brute force protection)
- [ ] Endpoints with side effects (email, Stripe, DELETE): limited
- [ ] Per-User key for authenticated endpoints (not IP, not raw token)
- [ ] 429 responses handled gracefully on the frontend

### Race Conditions
- [ ] All usage counters incremented BEFORE the API call
- [ ] try/except around every expensive call with counter rollback on failure
- [ ] No "check → expensive action → increment" patterns anywhere

### Input Sanitization
- [ ] max_length on every Pydantic/Zod field that accepts user input
- [ ] Regex validation on fields with known formats
- [ ] No string concatenation for database queries
- [ ] AI system prompt separated from user input
- [ ] `DOMPurify.sanitize()` on every `dangerouslySetInnerHTML`
- [ ] `html.escape()` on any external string in server-rendered HTML

### Row Level Security
- [ ] RLS enabled on every Supabase table
- [ ] Explicit policy on every table (no implicit deny reliance)
- [ ] Privilege columns (plan, is_admin, limits, credits) NOT in a table with UPDATE policy
- [ ] Tested with second account — User B cannot access User A's data
- [ ] Tested privilege escalation — user cannot update own plan/limit/admin via PostgREST
- [ ] No security logic lives only in the frontend

### Auth & Middleware
- [ ] Token caching implemented (60s TTL, SHA256 key)
- [ ] Only successful validations cached

---

## New Project Setup — Do This First

Before writing any feature code:

1. Create `.env.local` / `.env` and immediately add to `.gitignore`
2. Add a separate `.gitignore` to any subfolder that has its own env files
3. Install rate limiting: slowapi (Python) or Upstash (Next.js)
4. Install input validation: Pydantic (Python) or Zod (TypeScript)
5. Install DOMPurify if the project renders any user or AI-generated HTML
6. Enable RLS on Supabase tables from day one — before any data is written
7. Only then: start building features

---

## Audit Prompt for Existing Projects

Use this prompt with an AI coding assistant to audit any existing project:

```
Analysiere das gesamte Projekt auf Sicherheitslücken. Ändere NICHTS — nur analysieren.

1. API Keys: Grep nach hardcodierten Keys, prüfe .gitignore für alle Ordner,
   prüfe git history, prüfe ob NEXT_PUBLIC_ Variablen Secrets enthalten.

2. Rate Limiting: Liste alle Endpoints auf. Welche haben Rate Limiting,
   welche nicht? Gibt es eine Rate-Limiting-Library installiert?

3. Race Conditions: Suche nach Patterns wo ein Limit geprüft wird, dann ein
   teurer API-Call gemacht wird, dann erst ein Counter inkrementiert wird.

4. Input Sanitization: Prüfe alle Pydantic/Zod-Models auf fehlende max_length.
   Suche nach dangerouslySetInnerHTML ohne DOMPurify.
   Suche nach HTML-String-Interpolation ohne html.escape().

5. RLS: Welche Supabase-Tabellen haben RLS? Welche haben explizite Policies?

6. Auth-Caching: Macht die Middleware bei jedem Request einen Supabase HTTP-Call?

Ausgabe: Status (Sicher / Achtung / Kritisch) pro Bereich, Datei + Zeile bei
Problemen, konkreter Fix-Vorschlag, Priorität. Sei ehrlich.
```

---

## Resources
- slowapi (FastAPI): https://slowapi.readthedocs.io
- Upstash Rate Limiting (Next.js): https://upstash.com/docs/redis/sdks/ratelimit-ts/overview
- Zod: https://zod.dev
- DOMPurify: https://github.com/cure53/DOMPurify
- Supabase RLS Guide: https://supabase.com/docs/guides/database/postgres/row-level-security
- Next.js Server Actions: https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations
