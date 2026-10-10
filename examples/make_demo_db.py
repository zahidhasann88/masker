#!/usr/bin/env python3
"""Create and seed the Masker demo database (SQLite).

Usage:
    python examples/make_demo_db.py [path.sqlite] [--customers N]

The data is synthetic and deterministic (fixed seed), so two runs produce
byte-identical databases -- which is what makes the determinism check in
``demo.sh`` meaningful.
"""

from __future__ import annotations

import argparse
import random
import sqlite3
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

FIRST = [
    "Amara",
    "Bilal",
    "Chloe",
    "Dmitri",
    "Esme",
    "Farid",
    "Greta",
    "Hana",
    "Idris",
    "Junko",
    "Kwame",
    "Lucia",
    "Mateo",
    "Nadia",
    "Omar",
    "Priya",
    "Quentin",
    "Rosa",
    "Sven",
    "Tamar",
    "Umar",
    "Vera",
    "Wren",
    "Xiomara",
    "Yusuf",
    "Zoe",
]
LAST = [
    "Ahmed",
    "Bianchi",
    "Costa",
    "Dubois",
    "Eriksen",
    "Ferreira",
    "Garcia",
    "Haddad",
    "Ivanov",
    "Jensen",
    "Kowalski",
    "Lindqvist",
    "Moreau",
    "Nakamura",
    "Okonkwo",
    "Petrov",
    "Quinn",
    "Rossi",
    "Silva",
    "Tanaka",
    "Ueda",
    "Vargas",
    "Weber",
]
CITIES = ["Lisbon", "Osaka", "Tallinn", "Bogota", "Nairobi", "Riga", "Porto", "Kyoto"]
STREETS = ["Rua das Flores", "Main Street", "Karl-Marx-Allee", "Via Roma", "Oude Gracht"]
SKUS = [f"SKU-{n:04d}" for n in range(1, 120)]
AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/126.0",
]
SUBJECTS = [
    "Order not delivered",
    "Wrong item received",
    "Refund request",
    "Change of address",
    "Invoice copy",
]


def luhn_check_digit(partial: str) -> str:
    digits = [int(c) for c in reversed(partial)]
    total = 0
    for index, value in enumerate(digits):
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return str((10 - total % 10) % 10)


def card_number(rng: random.Random) -> str:
    partial = "411111" + "".join(str(rng.randint(0, 9)) for _ in range(8))
    return partial + luhn_check_digit(partial)


def split_statements(sql: str) -> list[str]:
    """Split SQL on semicolons, ignoring ``--`` comments.

    sqlite3 executes one statement at a time, and a semicolon inside a comment
    would otherwise split it in the wrong place.
    """
    stripped = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    return [statement.strip() for statement in stripped.split(";") if statement.strip()]


def build(path: Path, *, customers: int = 400, orders_per_customer: int = 3) -> None:
    schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(20260101)
    conn = sqlite3.connect(path)
    try:
        for statement in split_statements(schema):
            conn.execute(statement)

        base_day = date(1975, 1, 1)
        created = datetime(2021, 1, 1)
        for customer_id in range(1, customers + 1):
            first, last = rng.choice(FIRST), rng.choice(LAST)
            conn.execute(
                "INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    customer_id,
                    f"{first.lower()}.{last.lower()}{customer_id}@corp.example",
                    f"{first} {last}",
                    f"+1 555 {rng.randint(100, 999)} {rng.randint(1000, 9999)}",
                    (base_day + timedelta(days=rng.randint(0, 14000))).isoformat(),
                    f"{rng.randint(1, 400)} {rng.choice(STREETS)}",
                    rng.choice(CITIES),
                    f"{rng.randint(1000, 9999)} {rng.choice('ABCDEFGH')}{rng.choice('ABCDEFGH')}",
                    rng.choice(["Portugal", "Japan", "Estonia", "Colombia", "Kenya"]),
                    f"{rng.randint(2, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.1",
                    (created + timedelta(days=customer_id % 700)).isoformat(sep=" "),
                ),
            )

        order_id = 0
        for customer_id in range(1, customers + 1):
            for _ in range(rng.randint(1, orders_per_customer)):
                order_id += 1
                conn.execute(
                    "INSERT INTO orders VALUES (?,?,?,?,?,?,?)",
                    (
                        order_id,
                        customer_id,
                        (created + timedelta(days=order_id % 900, hours=order_id % 24)).isoformat(
                            sep=" "
                        ),
                        round(rng.uniform(9.0, 900.0), 2),
                        f"{rng.randint(1, 400)} {rng.choice(STREETS)}, {rng.choice(CITIES)}",
                        card_number(rng),
                        "Gift wrap please; the recipient lives at 12 Main St with A. Ahmed."
                        if rng.random() < 0.2
                        else None,
                    ),
                )
                for sku in rng.sample(SKUS, rng.randint(1, 3)):
                    conn.execute(
                        "INSERT INTO order_items VALUES (?,?,?,?)",
                        (order_id, sku, rng.randint(1, 5), round(rng.uniform(4.0, 199.0), 2)),
                    )

        for employee_id in range(1, 41):
            first, last = rng.choice(FIRST), rng.choice(LAST)
            conn.execute(
                "INSERT INTO employees VALUES (?,?,?,?,?,?,?)",
                (
                    employee_id,
                    None if employee_id <= 3 else employee_id - rng.randint(1, 3),
                    f"{first.lower()}.{last.lower()}{employee_id}@corp.example",
                    f"{first} {last}",
                    f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
                    rng.randint(38_000, 145_000),
                    (base_day + timedelta(days=rng.randint(12_000, 17_000))).isoformat(),
                ),
            )

        for ticket_id in range(1, 251):
            customer_id = rng.randint(1, customers)
            conn.execute(
                "INSERT INTO support_tickets VALUES (?,?,?,?,?,?)",
                (
                    ticket_id,
                    customer_id,
                    rng.randint(1, 40),
                    rng.choice(SUBJECTS),
                    f"Hi, this is customer {customer_id}. My card ends "
                    f"{rng.randint(1000, 9999)} and I can be reached on "
                    f"+1 555 {rng.randint(100, 999)} {rng.randint(1000, 9999)}.",
                    (created + timedelta(days=ticket_id)).isoformat(sep=" "),
                ),
            )

        for session_id in range(1, 901):
            conn.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?)",
                (
                    session_id,
                    rng.randint(1, customers),
                    f"{rng.randint(2, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}."
                    f"{rng.randint(1, 254)}",
                    rng.choice(AGENTS),
                    (created + timedelta(hours=session_id)).isoformat(sep=" "),
                ),
            )

        for supplier_id in range(1, 7):
            conn.execute(
                "INSERT INTO suppliers VALUES (?,?,?,?)",
                (
                    supplier_id,
                    f"{rng.choice(LAST)} Supply Co",
                    f"contact{supplier_id}@supplier.example",
                    supplier_id,
                ),
            )
        for warehouse_id in range(1, 7):
            conn.execute(
                "INSERT INTO warehouses VALUES (?,?,?)",
                (warehouse_id, f"Warehouse {warehouse_id}", warehouse_id),
            )

        conn.commit()
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default="demo.sqlite", help="SQLite file to create")
    parser.add_argument("--customers", type=int, default=400, help="Customers to generate")
    parser.add_argument("--orders-per-customer", type=int, default=3, help="Orders per customer")
    args = parser.parse_args(argv)
    target = Path(args.path)
    build(target, customers=args.customers, orders_per_customer=args.orders_per_customer)
    print(f"Wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
