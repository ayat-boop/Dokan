"""SQLite layer for Dokan. Standard library only."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DOKAN_DATA", os.path.join(BASE, "data"))
DB_PATH = os.path.join(DATA, "shop.db")

DEFAULT_SETTINGS = {
    "shop_name_en": "Dokan",
    "shop_name_bn": "দোকান",
    "tagline_en": "Everyday things, delivered to your door",
    "tagline_bn": "প্রতিদিনের দরকারি জিনিস, আপনার দরজায়",
    "announcement_en": "Free delivery on orders over ৳3,000",
    "announcement_bn": "৳৩,০০০ এর বেশি অর্ডারে ডেলিভারি ফ্রি",
    "whatsapp": "8801943156941",
    "bkash_number": "01943156941",
    "bkash_account_type": "Personal",
    "bkash_enabled": "1",
    "cod_enabled": "1",
    "delivery_dhaka": "60",
    "delivery_outside": "120",
    "free_delivery_min": "3000",
    "address_en": "Dhaka, Bangladesh",
    "address_bn": "ঢাকা, বাংলাদেশ",
    "email": "",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  must_change INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY,
  name_en TEXT NOT NULL, name_bn TEXT NOT NULL,
  desc_en TEXT NOT NULL DEFAULT '', desc_bn TEXT NOT NULL DEFAULT '',
  category_en TEXT NOT NULL DEFAULT '', category_bn TEXT NOT NULL DEFAULT '',
  price INTEGER NOT NULL, sale_price INTEGER,
  stock INTEGER NOT NULL DEFAULT 0,
  image TEXT NOT NULL DEFAULT '', gallery TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1, featured INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY, order_no TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL,
  area TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
  subtotal INTEGER NOT NULL, delivery INTEGER NOT NULL, total INTEGER NOT NULL,
  payment_method TEXT NOT NULL,
  bkash_sender TEXT NOT NULL DEFAULT '', bkash_trx TEXT NOT NULL DEFAULT '',
  payment_status TEXT NOT NULL, status TEXT NOT NULL,
  created INTEGER NOT NULL, updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER, name_en TEXT NOT NULL, name_bn TEXT NOT NULL,
  price INTEGER NOT NULL, qty INTEGER NOT NULL, image TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created);
CREATE INDEX IF NOT EXISTS idx_items_order ON order_items(order_id);
"""

SEED_PRODUCTS = [
    dict(name_en="Wireless Headphones", name_bn="ওয়্যারলেস হেডফোন",
         desc_en="Over-ear Bluetooth headphones with soft ear cushions, deep bass and up to 30 hours of battery life.",
         desc_bn="নরম ইয়ার কুশন, গভীর বেস এবং ৩০ ঘণ্টা পর্যন্ত ব্যাটারি ব্যাকআপ সহ ব্লুটুথ হেডফোন।",
         category_en="Electronics", category_bn="ইলেকট্রনিক্স", price=2490, sale_price=1990, stock=25,
         image="/static/img/products/headphones.svg", featured=1),
    dict(name_en="Smart Watch", name_bn="স্মার্ট ওয়াচ",
         desc_en="Track steps, heart rate and sleep. Water resistant, with a bright touch display.",
         desc_bn="স্টেপ, হার্ট রেট ও ঘুম ট্র্যাক করুন। পানি প্রতিরোধী, উজ্জ্বল টাচ ডিসপ্লে।",
         category_en="Electronics", category_bn="ইলেকট্রনিক্স", price=3290, sale_price=2790, stock=18,
         image="/static/img/products/watch.svg", featured=1),
    dict(name_en="Everyday Backpack", name_bn="ডেইলি ব্যাকপ্যাক",
         desc_en="Water-resistant fabric, a padded laptop sleeve and comfortable shoulder straps.",
         desc_bn="পানি প্রতিরোধী কাপড়, প্যাডেড ল্যাপটপ পকেট এবং আরামদায়ক স্ট্র্যাপ।",
         category_en="Fashion", category_bn="ফ্যাশন", price=1850, sale_price=None, stock=30,
         image="/static/img/products/backpack.svg", featured=1),
    dict(name_en="Running Sneakers", name_bn="রানিং স্নিকার্স",
         desc_en="Lightweight and breathable, with a cushioned sole for all-day comfort.",
         desc_bn="হালকা ও আরামদায়ক, সারাদিন পরার জন্য কুশনযুক্ত সোল।",
         category_en="Fashion", category_bn="ফ্যাশন", price=2950, sale_price=2450, stock=40,
         image="/static/img/products/sneakers.svg", featured=0),
    dict(name_en="Steel Water Bottle", name_bn="স্টিলের পানির বোতল",
         desc_en="Double-wall stainless steel keeps drinks cold for 24 hours or hot for 12.",
         desc_bn="ডাবল-ওয়াল স্টেইনলেস স্টিল, ঠান্ডা ২৪ ঘণ্টা ও গরম ১২ ঘণ্টা।",
         category_en="Home & Lifestyle", category_bn="হোম ও লাইফস্টাইল", price=690, sale_price=None, stock=60,
         image="/static/img/products/bottle.svg", featured=0),
]


def connect():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)  # we manage transactions
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


def hash_password(password, salt=None, iterations=200_000):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return f"pbkdf2${iterations}${salt}${dk.hex()}"


def check_password(password, stored):
    try:
        _, iters, salt, digest = stored.split("$")
        test = hash_password(password, salt, int(iters)).split("$")[3]
        return hmac.compare_digest(test, digest)
    except Exception:
        return False


def secret_key():
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with open(path) as f:
        return f.read().strip().encode()


def init():
    con = connect()
    try:
        con.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        now = int(time.time())
        seeded = con.execute("SELECT value FROM settings WHERE key='seeded'").fetchone()
        if not seeded:
            for p in SEED_PRODUCTS:
                con.execute(
                    """INSERT INTO products(name_en,name_bn,desc_en,desc_bn,category_en,category_bn,price,
                       sale_price,stock,image,gallery,active,featured,created,updated)
                       VALUES(?,?,?,?,?,?,?,?,?,?,'[]',1,?,?,?)""",
                    (p["name_en"], p["name_bn"], p["desc_en"], p["desc_bn"], p["category_en"],
                     p["category_bn"], p["price"], p["sale_price"], p["stock"], p["image"],
                     p["featured"], now, now))
            con.execute("INSERT INTO settings(key,value) VALUES('seeded','1')")
        if not con.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            pw = os.environ.get("DOKAN_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
            con.execute("INSERT INTO admins(username,pw_hash,must_change) VALUES('admin',?,?)",
                        (hash_password(pw), 0 if os.environ.get("DOKAN_ADMIN_PASSWORD") else 1))
            if not os.environ.get("DOKAN_ADMIN_PASSWORD"):
                path = os.path.join(DATA, "ADMIN_PASSWORD.txt")
                with open(path, "w") as f:
                    f.write(f"username: admin\npassword: {pw}\n")
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                print(f"\n  First run: admin login is  admin / {pw}\n  (also saved in {path})\n")
    finally:
        con.close()


def get_settings(con):
    return {r["key"]: r["value"] for r in con.execute("SELECT key,value FROM settings")}
