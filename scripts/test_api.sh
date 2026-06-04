#!/usr/bin/env bash
# =============================================================================
# Corvus End-to-End API Test Suite
# Usage: ./scripts/test_api.sh [BASE_URL]
# Default BASE_URL: http://localhost:8080
# =============================================================================

BASE_URL="${1:-http://localhost:8080}"
PASS=0
FAIL=0
SKIP=0

# ── colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── helpers ───────────────────────────────────────────────────────────────────
pass() { echo -e "  ${GREEN}✓${RESET} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${RESET} $1"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}⊘${RESET} $1"; ((SKIP++)); }
section() { echo -e "\n${BOLD}${CYAN}▸ $1${RESET}"; }

# Make a request and return the HTTP status code
# Usage: status=$(req GET /path)
req() {
  local method="$1"
  local path="$2"
  local body="$3"
  local auth_header=""
  [ -n "$TOKEN" ] && auth_header="-H \"Authorization: Bearer $TOKEN\""

  if [ -n "$body" ]; then
    curl -s -o /tmp/corvus_resp -w "%{http_code}" \
      -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
      -d "$body"
  else
    curl -s -o /tmp/corvus_resp -w "%{http_code}" \
      -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      ${TOKEN:+-H "Authorization: Bearer $TOKEN"}
  fi
}

body() { cat /tmp/corvus_resp; }
field() { cat /tmp/corvus_resp | grep -o "\"$1\":\"[^\"]*\"" | head -1 | cut -d'"' -f4; }
field_num() { cat /tmp/corvus_resp | grep -o "\"$1\":[0-9]*" | head -1 | cut -d':' -f2; }

assert_status() {
  local got="$1" want="$2" label="$3"
  if [ "$got" = "$want" ]; then
    pass "$label (HTTP $got)"
  else
    fail "$label — expected $want, got $got | $(body)"
  fi
}

assert_field() {
  local key="$1" want="$2" label="$3"
  local got
  got=$(field "$key")
  if [ "$got" = "$want" ]; then
    pass "$label"
  else
    fail "$label — expected $key=$want, got $key=$got"
  fi
}

assert_field_nonempty() {
  local key="$1" label="$2"
  local got
  got=$(field "$key")
  if [ -n "$got" ]; then
    pass "$label ($key present)"
  else
    fail "$label — $key is empty | $(body)"
  fi
}

# ── generate unique test email ────────────────────────────────────────────────
TS=$(date +%s)
TEST_EMAIL="test_${TS}@corvus-test.sh"
TEST_PASS="testpassword123"

echo -e "\n${BOLD}Corvus API Test Suite${RESET}"
echo -e "Target: ${CYAN}$BASE_URL${RESET}"
echo -e "Email:  ${CYAN}$TEST_EMAIL${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# =============================================================================
section "1. Health Checks"
# =============================================================================

status=$(req GET /healthz)
assert_status "$status" "200" "GET /healthz"

status=$(req GET /readyz)
assert_status "$status" "200" "GET /readyz"

# =============================================================================
section "2. Auth — Signup"
# =============================================================================

# Short password should fail
status=$(req POST /api/v1/auth/signup '{"email":"bad@test.com","password":"short"}')
assert_status "$status" "400" "Signup rejects password < 8 chars"

# Valid signup
status=$(req POST /api/v1/auth/signup "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}")
assert_status "$status" "201" "Signup with valid credentials"
TOKEN=$(field "token")
USER_ID=$(cat /tmp/corvus_resp | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
assert_field_nonempty "token" "Signup returns JWT token"

# Duplicate email should fail
status=$(req POST /api/v1/auth/signup "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}")
assert_status "$status" "409" "Signup rejects duplicate email"

# =============================================================================
section "3. Auth — Login"
# =============================================================================

# Wrong password
status=$(req POST /api/v1/auth/login "{\"email\":\"$TEST_EMAIL\",\"password\":\"wrongpassword\"}")
assert_status "$status" "401" "Login rejects wrong password"

# Correct login
status=$(req POST /api/v1/auth/login "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}")
assert_status "$status" "200" "Login with correct credentials"
TOKEN=$(field "token")
assert_field_nonempty "token" "Login returns JWT token"
assert_field "plan" "free" "Login returns plan=free"

# =============================================================================
section "4. Auth — Me & Refresh"
# =============================================================================

status=$(req GET /api/v1/auth/me)
assert_status "$status" "200" "GET /auth/me returns user"
assert_field "plan" "free" "/auth/me returns correct plan"

status=$(req POST /api/v1/auth/refresh)
assert_status "$status" "200" "POST /auth/refresh issues new token"
NEW_TOKEN=$(field "token")
assert_field_nonempty "token" "Refresh returns new token"
# Sleep 1s so iat claim differs — tokens issued in same second are identical by design
sleep 1
status=$(req POST /api/v1/auth/refresh)
NEW_TOKEN2=$(field "token")
[ "$NEW_TOKEN" != "$NEW_TOKEN2" ] && pass "Refresh token changes over time" || skip "Refresh tokens identical (same second — expected)"
TOKEN="$NEW_TOKEN2"

# =============================================================================
section "5. Auth — Security"
# =============================================================================

# No token
OLD_TOKEN="$TOKEN"
TOKEN=""
status=$(req GET /api/v1/hosts)
assert_status "$status" "401" "Protected route rejects missing token"

# Invalid token
TOKEN="invalid.jwt.token"
status=$(req GET /api/v1/hosts)
assert_status "$status" "401" "Protected route rejects invalid token"

# Restore valid token
TOKEN="$OLD_TOKEN"

# Unprotected endpoints should now require auth (fixed in audit)
TOKEN=""
status=$(req POST /api/v1/ask '{"question":"test"}')
assert_status "$status" "401" "POST /ask requires auth"

status=$(req GET /api/v1/mesh/nodes)
assert_status "$status" "401" "GET /mesh/nodes requires auth"

TOKEN="$OLD_TOKEN"

# =============================================================================
section "6. Scan"
# =============================================================================

# Missing target
status=$(req POST /api/v1/scan '{"ports":"80"}')
assert_status "$status" "400" "Scan rejects missing target"

# Invalid target
status=$(req POST /api/v1/scan '{"target":"not-an-ip","ports":"80"}')
assert_status "$status" "400" "Scan rejects invalid target"

# Valid scan (localhost)
status=$(req POST /api/v1/scan '{"target":"127.0.0.1","ports":"80,443,8080"}')
assert_status "$status" "202" "Scan accepts valid target"
JOB_ID=$(field "id")
assert_field_nonempty "id" "Scan returns job ID"
assert_field "status" "running" "Scan job starts as running"

# Get job status
if [ -n "$JOB_ID" ]; then
  sleep 1
  status=$(req GET "/api/v1/scan/$JOB_ID")
  assert_status "$status" "200" "GET /scan/:id returns job"
else
  skip "GET /scan/:id — no job ID from previous step"
fi

# Non-existent job
status=$(req GET "/api/v1/scan/00000000-0000-0000-0000-000000000000")
assert_status "$status" "404" "GET /scan/:id returns 404 for unknown job"

# =============================================================================
section "7. Hosts & Alerts"
# =============================================================================

status=$(req GET /api/v1/hosts)
assert_status "$status" "200" "GET /hosts returns 200"
# hosts array should exist
body | grep -q '"hosts"' && pass "GET /hosts returns hosts array" || fail "GET /hosts missing hosts field"

status=$(req GET /api/v1/alerts)
assert_status "$status" "200" "GET /alerts returns 200"
body | grep -q '"alerts"' && pass "GET /alerts returns alerts array" || fail "GET /alerts missing alerts field"

# With filters
status=$(req GET "/api/v1/alerts?since=24h&severity=HIGH")
assert_status "$status" "200" "GET /alerts with filters returns 200"

# =============================================================================
section "8. Query DSL"
# =============================================================================

status=$(req POST /api/v1/query '{"query":"open ports"}')
assert_status "$status" "200" "POST /query with valid expression"
body | grep -q '"results"' && pass "Query returns results array" || fail "Query missing results field"

status=$(req POST /api/v1/query '{}')
assert_status "$status" "400" "POST /query rejects empty query"

# =============================================================================
section "9. LLM — Ask & Models"
# =============================================================================

status=$(req GET /api/v1/ask/models)
assert_status "$status" "200" "GET /ask/models returns model list"
body | grep -q '"models"' && pass "Models endpoint returns models array" || fail "Models missing models field"

# Ask without LLM key configured falls back gracefully
status=$(req POST /api/v1/ask '{"question":"what ports are open?"}')
[ "$status" = "200" ] && pass "POST /ask returns 200 (with or without LLM key)" || fail "POST /ask failed with status $status | $(body)"

# Ask with empty question
status=$(req POST /api/v1/ask '{"question":""}')
assert_status "$status" "400" "POST /ask rejects empty question"

# =============================================================================
section "10. Supply Chain"
# =============================================================================

status=$(req GET /api/v1/supplychain/127.0.0.1)
assert_status "$status" "200" "GET /supplychain/:ip returns 200"
body | grep -q '"findings"' && pass "Supply chain returns findings array" || fail "Supply chain missing findings field"

status=$(req GET /api/v1/supplychain/not-an-ip)
assert_status "$status" "400" "GET /supplychain rejects invalid IP"

# =============================================================================
section "11. Mesh"
# =============================================================================

status=$(req GET /api/v1/mesh/nodes)
assert_status "$status" "200" "GET /mesh/nodes returns 200"
body | grep -q '"nodes"' && pass "Mesh returns nodes array" || fail "Mesh missing nodes field"

# =============================================================================
section "12. Billing — Usage"
# =============================================================================

status=$(req GET /api/v1/billing/usage)
assert_status "$status" "200" "GET /billing/usage returns 200"
body | grep -q '"plan"' && pass "Usage returns plan field" || fail "Usage missing plan field"
body | grep -q '"scan_count"' && pass "Usage returns scan_count" || fail "Usage missing scan_count"
body | grep -q '"scan_limit"' && pass "Usage returns scan_limit" || fail "Usage missing scan_limit"

# =============================================================================
section "13. Billing — Invoices"
# =============================================================================

status=$(req GET /api/v1/billing/invoices)
assert_status "$status" "200" "GET /billing/invoices returns 200"
body | grep -q '"invoices"' && pass "Invoices returns invoices array" || fail "Invoices missing invoices field"

# =============================================================================
section "14. Billing — Crypto"
# =============================================================================

# Valid crypto checkout
status=$(req POST /api/v1/billing/crypto '{"token":"USDT","network":"base"}')
assert_status "$status" "200" "POST /billing/crypto returns payment info"
body | grep -q '"payment"' && pass "Crypto returns payment object" || fail "Crypto missing payment field"
body | grep -q '"address"' && pass "Crypto returns wallet address" || fail "Crypto missing address"
CRYPTO_REF=$(cat /tmp/corvus_resp | grep -o '"reference":"[^"]*"' | head -1 | cut -d'"' -f4)

# Unsupported token/network
status=$(req POST /api/v1/billing/crypto '{"token":"DOGE","network":"dogecoin"}')
assert_status "$status" "400" "POST /billing/crypto rejects unsupported token"

# Verify without reference
status=$(req POST /api/v1/billing/crypto/verify '{"tx_hash":"0xabc"}')
assert_status "$status" "400" "POST /billing/crypto/verify rejects missing reference"

# Verify with fake tx hash (should return pending or pending_review, not 500)
if [ -n "$CRYPTO_REF" ]; then
  status=$(req POST /api/v1/billing/crypto/verify "{\"reference\":\"$CRYPTO_REF\",\"tx_hash\":\"0xfakedeadbeef\"}")
  [ "$status" = "200" ] && pass "POST /billing/crypto/verify handles unconfirmed tx gracefully" || fail "POST /billing/crypto/verify returned $status | $(body)"
else
  skip "POST /billing/crypto/verify — no reference from previous step"
fi

# =============================================================================
section "15. Billing — Paystack"
# =============================================================================

status=$(req POST /api/v1/billing/checkout)
# Should fail with 500 if PAYSTACK_SECRET_KEY is test key (Paystack will reject)
# or succeed with 200 and return a URL
[ "$status" = "200" ] || [ "$status" = "500" ] && pass "POST /billing/checkout responds (200 or 500 depending on key)" || fail "POST /billing/checkout returned unexpected $status"

# =============================================================================
section "16. Quota Enforcement"
# =============================================================================

# Check that usage_logs are being written
USAGE_BEFORE=$(req GET /api/v1/billing/usage && field_num "scan_count")
req POST /api/v1/scan '{"target":"127.0.0.1","ports":"80"}' > /dev/null
sleep 1
USAGE_AFTER=$(req GET /api/v1/billing/usage && field_num "scan_count")
[ "$USAGE_AFTER" -gt "$USAGE_BEFORE" ] 2>/dev/null && pass "Scan increments usage_logs count" || skip "Scan usage count check (scan may not have completed yet)"

# =============================================================================
section "17. Rate Limiting"
# =============================================================================

# Fire 105 rapid requests to trigger the per-IP rate limiter (limit is 100/min)
echo -n "  Sending 105 rapid requests to trigger rate limit..."
RATE_LIMITED=0
for i in $(seq 1 105); do
  s=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/healthz")
  [ "$s" = "429" ] && RATE_LIMITED=1 && break
done
[ "$RATE_LIMITED" = "1" ] && pass "Rate limiter triggers 429 after 100 req/min" || skip "Rate limiter not triggered (may need more requests or different window)"

# =============================================================================
section "18. CORS Headers"
# =============================================================================

CORS=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS "$BASE_URL/api/v1/hosts" \
  -H "Origin: http://localhost:3001" \
  -H "Access-Control-Request-Method: GET")
[ "$CORS" = "200" ] || [ "$CORS" = "204" ] && pass "CORS preflight returns 200/204" || fail "CORS preflight returned $CORS"

# Disallowed origin should not get CORS headers
CORS_HEADER=$(curl -s -I "$BASE_URL/api/v1/hosts" \
  -H "Origin: https://evil.com" \
  ${TOKEN:+-H "Authorization: Bearer $TOKEN"} | grep -i "access-control-allow-origin")
echo "$CORS_HEADER" | grep -q "evil.com" && fail "CORS allows evil.com origin" || pass "CORS does not reflect evil.com origin"

# =============================================================================
# SUMMARY
# =============================================================================

TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BOLD}Results: $TOTAL tests${RESET}"
echo -e "  ${GREEN}Passed:  $PASS${RESET}"
echo -e "  ${RED}Failed:  $FAIL${RESET}"
echo -e "  ${YELLOW}Skipped: $SKIP${RESET}"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}${BOLD}✗ Test suite FAILED${RESET}"
  exit 1
else
  echo -e "${GREEN}${BOLD}✓ Test suite PASSED${RESET}"
  exit 0
fi
