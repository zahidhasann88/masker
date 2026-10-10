#!/usr/bin/env bash
#
# End-to-end Masker demo on SQLite: init, scan, validate, run, verify, report,
# plus three proofs -- determinism, foreign-key consistency, and that `verify`
# catches a deliberately unmasked column.
#
#   ./examples/demo.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

WORK="${MASKER_DEMO_DIR:-$(mktemp -d)}"
SOURCE="$WORK/demo.sqlite"
TARGET="$WORK/masked.sqlite"
TARGET2="$WORK/masked-again.sqlite"
LEAKY="$WORK/leaky.sqlite"
RULES="examples/masker.yaml"

export MASKER_SECRET_KEY="${MASKER_SECRET_KEY:-demo-key-please-change-me-0123456789}"

# Find a masker to run: an explicit $MASKER, then the installed CLI, then a
# virtualenv in this checkout, then the current interpreter.
if [ -n "${MASKER:-}" ]; then
    :
elif command -v masker >/dev/null 2>&1; then
    MASKER="masker"
elif [ -x ".venv/bin/masker" ]; then
    MASKER=".venv/bin/masker"
elif [ -x "venv/bin/masker" ]; then
    MASKER="venv/bin/masker"
else
    MASKER="python3 -m masker"
fi
PYTHON="${PYTHON:-python3}"
echo "Using: $MASKER"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "0. Build the demo database ($SOURCE)"
"$PYTHON" examples/make_demo_db.py "$SOURCE"

step "1. masker init -- generate a starter rules file"
$MASKER init --source "sqlite:///$SOURCE" --output "$WORK/masker.generated.yaml" --force
echo "--- the first suggestion it made:"
grep -A 5 -m 1 "^        # SUGGESTED" "$WORK/masker.generated.yaml" | sed 's/^/    /'

step "2. masker scan -- what looks like PII? (no rules file yet)"
$MASKER scan --source "sqlite:///$SOURCE" --sample-size 100 > "$WORK/scan.txt"
tail -22 "$WORK/scan.txt"

step "3. masker scan --strict -- fails while PII is unmasked"
set +e
$MASKER scan --source "sqlite:///$SOURCE" --sample-size 100 --strict >/dev/null 2>&1
status=$?
set -e
echo "    exit code $status (1 expected -- no column has a rule yet)"
[ "$status" -eq 1 ] || { echo "    unexpected: --strict passed"; exit 1; }

step "4. masker scan --strict --rules examples/masker.yaml -- now it passes"
$MASKER scan --source "sqlite:///$SOURCE" --rules "$RULES" --sample-size 100 \
    --strict > "$WORK/scan-reviewed.txt"
tail -3 "$WORK/scan-reviewed.txt"

step "5. masker validate -- check the rules against the schema"
$MASKER validate --rules "$RULES" --source "sqlite:///$SOURCE" > "$WORK/validate.txt"
tail -6 "$WORK/validate.txt"

step "6. masker run --dry-run -- the plan, with originals partially hidden"
$MASKER run --source "sqlite:///$SOURCE" --target "sqlite:///$TARGET" \
    --rules "$RULES" --dry-run > "$WORK/dryrun.txt"
head -34 "$WORK/dryrun.txt"

step "7. masker run -- copy the schema and masked data"
$MASKER run --source "sqlite:///$SOURCE" --target "sqlite:///$TARGET" \
    --rules "$RULES" --yes --batch-size 500 --stats-file "$WORK/run1.json" > "$WORK/run1.txt"
tail -18 "$WORK/run1.txt"

step "8. masker verify -- look for originals in the target"
set +e
$MASKER verify --source "sqlite:///$SOURCE" --target "sqlite:///$TARGET" \
    --rules "$RULES" > "$WORK/verify.txt"
status=$?
set -e
tail -14 "$WORK/verify.txt"
echo "    verify exit code $status (0 expected)"
[ "$status" -eq 0 ] || { echo "    unexpected: verify reported a leak"; exit 1; }

step "9. masker report -- markdown summary of the run"
$MASKER report --input "$WORK/run1.json" --format markdown --output "$WORK/report.md"
sed -n '1,20p' "$WORK/report.md" | sed 's/^/    /'

step "10. Determinism -- a second run with a different batch size"
$MASKER run --source "sqlite:///$SOURCE" --target "sqlite:///$TARGET2" \
    --rules "$RULES" --yes --batch-size 37 --stats-file "$WORK/run2.json" >/dev/null
"$PYTHON" - "$TARGET" "$TARGET2" <<'PY'
import sqlite3, sys
a, b = (sqlite3.connect(path) for path in sys.argv[1:3])
queries = {
    "customers": "SELECT id, email, full_name, dob, address FROM customers ORDER BY id",
    "orders": "SELECT id, customer_id, total, card_number FROM orders ORDER BY id",
    "employees": "SELECT id, manager_id, email, ssn, salary FROM employees ORDER BY id",
}
ok = True
for name, query in queries.items():
    same = a.execute(query).fetchall() == b.execute(query).fetchall()
    ok = ok and same
    print(f"    {name:12} {'identical' if same else 'DIFFERS'}")
print("    determinism:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY

step "11. Foreign keys -- every masked reference still resolves"
"$PYTHON" - "$TARGET" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
checks = {
    "orders.customer_id -> customers.id":
        "SELECT COUNT(*) FROM orders o LEFT JOIN customers c ON o.customer_id = c.id"
        " WHERE c.id IS NULL",
    "order_items.order_id -> orders.id":
        "SELECT COUNT(*) FROM order_items i LEFT JOIN orders o ON i.order_id = o.id"
        " WHERE o.id IS NULL",
    "employees.manager_id -> employees.id":
        "SELECT COUNT(*) FROM employees e LEFT JOIN employees m ON e.manager_id = m.id"
        " WHERE e.manager_id IS NOT NULL AND m.id IS NULL",
    "sessions.customer_id -> customers.id":
        "SELECT COUNT(*) FROM sessions s LEFT JOIN customers c ON s.customer_id = c.id"
        " WHERE c.id IS NULL",
    "warehouses.primary_supplier_id -> suppliers.id":
        "SELECT COUNT(*) FROM warehouses w LEFT JOIN suppliers s"
        " ON w.primary_supplier_id = s.id WHERE s.id IS NULL",
}
failed = False
for label, query in checks.items():
    orphans = conn.execute(query).fetchone()[0]
    failed = failed or orphans != 0
    print(f"    {label:46} orphans={orphans}")
joined = conn.execute(
    "SELECT COUNT(*) FROM orders o JOIN customers c ON o.customer_id = c.id"
).fetchone()[0]
print(f"    orders that still join to their customer:      {joined}")
print("    foreign keys:", "FAIL" if failed else "PASS")
sys.exit(1 if failed else 0)
PY

step "12. verify catches a deliberately unmasked column"
sed '/transformer: email}/d' "$RULES" > "$WORK/masker.leaky.yaml"
echo "    removed every 'email' rule; remaining: $(grep -c 'transformer: email' "$WORK/masker.leaky.yaml")"
$MASKER run --source "sqlite:///$SOURCE" --target "sqlite:///$LEAKY" \
    --rules "$WORK/masker.leaky.yaml" --yes --stats-file "$WORK/run3.json" >/dev/null
set +e
output=$($MASKER verify --source "sqlite:///$SOURCE" --target "sqlite:///$LEAKY" \
    --rules "$WORK/masker.leaky.yaml" --sample-size 100 2>&1)
status=$?
set -e
echo "$output" | grep -E "leak|MISSING" | head -4 | sed 's/^/    /'
echo "    verify exit code $status (1 expected)"
[ "$status" -eq 1 ] || { echo "    unexpected: verify did not flag the leak"; exit 1; }

printf '\n\033[1mDemo finished.\033[0m Artifacts are in %s\n' "$WORK"
