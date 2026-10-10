-- Demo schema for Masker: a small e-commerce database.
--
-- It deliberately contains the shapes that make masking interesting:
--   * a UNIQUE column            (customers.email, employees.email, employees.ssn)
--   * plain foreign keys          (orders -> customers, order_items -> orders)
--   * a self-referencing FK       (employees.manager_id -> employees.id)
--   * a two-table FK cycle        (warehouses <-> suppliers)
--   * a composite primary key     (order_items)
--   * free text that hides PII    (support_tickets.body, orders.notes)
--
-- Works on SQLite as-is; other backends need their own type spellings.

CREATE TABLE customers (
    id          INTEGER PRIMARY KEY,
    email       VARCHAR(160) NOT NULL UNIQUE,
    full_name   VARCHAR(120) NOT NULL,
    phone       VARCHAR(32),
    dob         DATE,
    address     VARCHAR(200),
    city        VARCHAR(80),
    postcode    VARCHAR(16),
    country     VARCHAR(64),
    ip_address  VARCHAR(45),
    created_at  TIMESTAMP NOT NULL
);

CREATE TABLE orders (
    id            INTEGER PRIMARY KEY,
    customer_id   INTEGER NOT NULL REFERENCES customers(id),
    placed_at     TIMESTAMP NOT NULL,
    total         NUMERIC(10, 2) NOT NULL,
    ship_to       VARCHAR(200),
    card_number   VARCHAR(24),
    notes         TEXT
);

CREATE TABLE order_items (
    order_id    INTEGER NOT NULL REFERENCES orders(id),
    sku         VARCHAR(40) NOT NULL,
    quantity    INTEGER NOT NULL,
    unit_price  NUMERIC(10, 2) NOT NULL,
    PRIMARY KEY (order_id, sku)
);

CREATE TABLE employees (
    id          INTEGER PRIMARY KEY,
    manager_id  INTEGER REFERENCES employees(id),
    email       VARCHAR(160) NOT NULL UNIQUE,
    full_name   VARCHAR(120) NOT NULL,
    ssn         VARCHAR(11) UNIQUE,
    salary      INTEGER,
    hired_on    DATE
);

CREATE TABLE support_tickets (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER REFERENCES customers(id),
    employee_id  INTEGER REFERENCES employees(id),
    subject      VARCHAR(200),
    body         TEXT,
    opened_at    TIMESTAMP
);

CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER REFERENCES customers(id),
    ip_address   VARCHAR(45),
    user_agent   VARCHAR(255),
    started_at   TIMESTAMP
);

-- A deliberate two-table FK cycle: warehouses and suppliers point at each
-- other, so neither can be loaded first without deferring the checks.
CREATE TABLE suppliers (
    id                    INTEGER PRIMARY KEY,
    name                  VARCHAR(120) NOT NULL,
    contact_email         VARCHAR(160),
    default_warehouse_id  INTEGER REFERENCES warehouses(id)
);

CREATE TABLE warehouses (
    id                    INTEGER PRIMARY KEY,
    label                 VARCHAR(80) NOT NULL,
    primary_supplier_id   INTEGER REFERENCES suppliers(id)
);

CREATE INDEX ix_orders_customer ON orders(customer_id);
CREATE INDEX ix_sessions_customer ON sessions(customer_id);
