#!/usr/bin/env python3
"""Dokan: a small e-commerce backend (WSGI, standard library only).

Run locally:   python3 app.py          -> http://localhost:8000
Production:    point any WSGI host (PythonAnywhere, gunicorn, waitress) at  wsgi:application
"""
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import threading
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

import db

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
UPLOADS = os.path.join(db.DATA, "uploads")
MAX_BODY = 6 * 1024 * 1024
SESSION_SECONDS = 12 * 3600
ORDER_STATUSES = ("new", "confirmed", "shipped", "delivered", "cancelled")
PAYMENT_STATUSES = ("cod", "pending", "paid", "rejected")

db.init()
SECRET = db.secret_key()
mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("image/webp", ".webp")

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'self'; form-action 'self'")


# ----------------------------------------------------------------------------- helpers
class ApiError(Exception):
    def __init__(self, message, status=400, code="error"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


class Req:
    def __init__(self, env):
        self.env = env
        self.method = env["REQUEST_METHOD"]
        self.path = env.get("PATH_INFO", "/") or "/"
        self.q = {k: v[0] for k, v in parse_qs(env.get("QUERY_STRING", ""), keep_blank_values=True).items()}
        fwd = env.get("HTTP_X_FORWARDED_FOR", "")
        self.ip = (fwd.split(",")[0].strip() if fwd else env.get("REMOTE_ADDR", "?"))
        self.secure = env.get("wsgi.url_scheme") == "https" or env.get("HTTP_X_FORWARDED_PROTO") == "https"
        self._body = None
        self.cookies = SimpleCookie(env.get("HTTP_COOKIE", ""))

    def body(self):
        if self._body is None:
            try:
                n = int(self.env.get("CONTENT_LENGTH") or 0)
            except ValueError:
                n = 0
            if n > MAX_BODY:
                raise ApiError("Request too large", 413, "too_large")
            self._body = self.env["wsgi.input"].read(n) if n else b""
        return self._body

    def json(self):
        if self.method in ("POST", "PUT", "DELETE"):
            if "application/json" not in self.env.get("CONTENT_TYPE", ""):
                raise ApiError("Content-Type must be application/json", 415, "bad_type")
        try:
            data = json.loads(self.body() or b"{}")
        except ValueError:
            raise ApiError("Invalid JSON", 400, "bad_json")
        if not isinstance(data, dict):
            raise ApiError("Invalid JSON", 400, "bad_json")
        return data


def jr(data, status=200, cookies=None):
    body = json.dumps(data, ensure_ascii=False).encode()
    headers = [("Content-Type", "application/json; charset=utf-8"), ("Cache-Control", "no-store")]
    for c in cookies or []:
        headers.append(("Set-Cookie", c))
    return status, headers, body


_hits, _hits_lock = {}, threading.Lock()


def rate_limit(key, limit, window):
    now = time.time()
    with _hits_lock:
        arr = [t for t in _hits.get(key, []) if now - t < window]
        if len(arr) >= limit:
            _hits[key] = arr
            raise ApiError("Too many attempts. Please wait a while and try again.", 429, "rate_limited")
        arr.append(now)
        _hits[key] = arr


def cs(v, maxlen, required=False, field="field"):
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(v if v is not None else "")).strip()
    if required and not s:
        raise ApiError(f"{field} is required", 400, "required")
    return s[:maxlen]


def to_int(v, field, lo=0, hi=10_000_000, required=True):
    if v in (None, ""):
        if required:
            raise ApiError(f"{field} is required", 400, "required")
        return None
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        raise ApiError(f"{field} must be a number", 400, "bad_number")
    if n < lo or n > hi:
        raise ApiError(f"{field} must be between {lo} and {hi}", 400, "bad_number")
    return n


def norm_phone(v):
    s = re.sub(r"[\s\-()]", "", str(v or ""))
    m = re.fullmatch(r"(?:\+?88)?(01[3-9]\d{8})", s)
    return m.group(1) if m else None


def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(payload):
    raw = b64e(json.dumps(payload).encode())
    return raw + "." + hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()


def verify(token):
    try:
        raw, sig = token.rsplit(".", 1)
        good = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(b64d(raw))
        return data if data.get("exp", 0) > time.time() else None
    except Exception:
        return None


def admin_name(req):
    c = req.cookies.get("dk_admin")
    data = verify(c.value) if c else None
    return data.get("u") if data else None


def need_admin(req):
    u = admin_name(req)
    if not u:
        raise ApiError("Please sign in", 401, "auth")
    return u


def session_cookie(req, value, max_age):
    c = f"dk_admin={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    return c + ("; Secure" if req.secure else "")


IMG_RE = re.compile(r"^/(static/img/products|uploads)/[A-Za-z0-9._-]+$")


def prod_dict(r, admin=False):
    d = {k: r[k] for k in ("id", "name_en", "name_bn", "desc_en", "desc_bn", "category_en", "category_bn",
                           "price", "sale_price", "stock", "image")}
    d["gallery"] = json.loads(r["gallery"] or "[]")
    d["featured"] = bool(r["featured"])
    if admin:
        d["active"] = bool(r["active"])
    return d


def read_product(d):
    name_en = cs(d.get("name_en"), 120)
    name_bn = cs(d.get("name_bn"), 120)
    if not (name_en or name_bn):
        raise ApiError("Enter a product name", 400, "required")
    name_en, name_bn = name_en or name_bn, name_bn or name_en
    desc_en, desc_bn = cs(d.get("desc_en"), 2000), cs(d.get("desc_bn"), 2000)
    cat_en, cat_bn = cs(d.get("category_en"), 60), cs(d.get("category_bn"), 60)
    cat_en, cat_bn = cat_en or cat_bn, cat_bn or cat_en
    price = to_int(d.get("price"), "Price", 1)
    sale = to_int(d.get("sale_price"), "Sale price", 1, required=False)
    if sale is not None and sale >= price:
        raise ApiError("Sale price must be lower than the regular price", 400, "bad_sale")
    stock = to_int(d.get("stock"), "Stock", 0, 100000)
    image = cs(d.get("image"), 200)
    if image and not IMG_RE.match(image):
        raise ApiError("Invalid image", 400, "bad_image")
    gallery = [g for g in (d.get("gallery") or []) if isinstance(g, str)][:4]
    if any(not IMG_RE.match(g) for g in gallery):
        raise ApiError("Invalid gallery image", 400, "bad_image")
    return dict(name_en=name_en, name_bn=name_bn, desc_en=desc_en, desc_bn=desc_bn, category_en=cat_en,
                category_bn=cat_bn, price=price, sale_price=sale, stock=stock, image=image,
                gallery=json.dumps(gallery), active=1 if d.get("active", True) else 0,
                featured=1 if d.get("featured") else 0)


# ----------------------------------------------------------------------------- public API
def api_settings(req, con):
    return jr({k: v for k, v in db.get_settings(con).items() if k != "seeded"})


def api_products(req, con):
    where, args = ["active=1"], []
    if req.q.get("ids"):
        ids = [int(i) for i in re.findall(r"\d+", req.q["ids"])][:50]
        where.append(f"id IN ({','.join('?' * len(ids)) or 'NULL'})")
        args += ids
    if req.q.get("cat"):
        where.append("category_en=?")
        args.append(req.q["cat"])
    if req.q.get("featured") == "1":
        where.append("featured=1")
    if req.q.get("sale") == "1":
        where.append("sale_price IS NOT NULL")
    term = req.q.get("q", "").strip()[:60]
    if term:
        like = f"%{term}%"
        where.append("(name_en LIKE ? OR name_bn LIKE ? OR desc_en LIKE ? OR desc_bn LIKE ? OR category_en LIKE ? OR category_bn LIKE ?)")
        args += [like] * 6
    order = {"price_asc": "COALESCE(sale_price,price) ASC", "price_desc": "COALESCE(sale_price,price) DESC",
             "new": "id DESC", "featured": "featured DESC, id DESC"}.get(req.q.get("sort", "new"), "id DESC")
    try:
        page = max(1, int(req.q.get("page", 1)))
        per = min(48, max(1, int(req.q.get("per", 12))))
    except ValueError:
        page, per = 1, 12
    w = " AND ".join(where)
    total = con.execute(f"SELECT COUNT(*) c FROM products WHERE {w}", args).fetchone()["c"]
    rows = con.execute(f"SELECT * FROM products WHERE {w} ORDER BY {order} LIMIT ? OFFSET ?",
                       args + [per, (page - 1) * per]).fetchall()
    cats = con.execute("SELECT category_en e, category_bn b, COUNT(*) n FROM products WHERE active=1 AND category_en!='' "
                       "GROUP BY category_en ORDER BY MIN(id)").fetchall()
    return jr({"items": [prod_dict(r) for r in rows], "total": total, "page": page,
               "pages": max(1, -(-total // per)), "categories": [dict(c) for c in cats]})


def api_product(req, con, pid):
    r = con.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
    if not r:
        raise ApiError("Product not found", 404, "not_found")
    return jr(prod_dict(r))


ORDER_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def api_create_order(req, con):
    rate_limit("order:" + req.ip, 10, 3600)
    d = req.json()
    st = db.get_settings(con)
    name = cs(d.get("name"), 80, True, "Name")
    phone = norm_phone(d.get("phone"))
    if not phone:
        raise ApiError("Enter a valid Bangladeshi mobile number (01XXXXXXXXX)", 400, "bad_phone")
    address = cs(d.get("address"), 300, True, "Address")
    if len(address) < 8:
        raise ApiError("Please enter your full address", 400, "short_address")
    area = d.get("area")
    if area not in ("dhaka", "outside"):
        raise ApiError("Choose a delivery area", 400, "bad_area")
    note = cs(d.get("note"), 300)
    method = d.get("payment")
    if method not in ("bkash", "cod") or st.get(f"{'bkash' if method == 'bkash' else 'cod'}_enabled") != "1":
        raise ApiError("Choose a payment method", 400, "bad_payment")
    sender, trx = "", ""
    if method == "bkash":
        sender = norm_phone(d.get("bkash_sender"))
        if not sender:
            raise ApiError("Enter the bKash number you paid from", 400, "bad_sender")
        trx = cs(d.get("bkash_trx"), 20).upper()
        if not re.fullmatch(r"[A-Z0-9]{8,12}", trx):
            raise ApiError("Enter the bKash Transaction ID (TrxID)", 400, "bad_trx")
    lines = d.get("items")
    if not isinstance(lines, list) or not 1 <= len(lines) <= 30:
        raise ApiError("Your cart is empty", 400, "empty_cart")
    merged = {}
    for ln in lines:
        pid = to_int(ln.get("id") if isinstance(ln, dict) else None, "Product", 1)
        merged[pid] = merged.get(pid, 0) + to_int(ln.get("qty"), "Quantity", 1, 20)
    con.execute("BEGIN IMMEDIATE")
    try:
        items, subtotal = [], 0
        for pid, qty in merged.items():
            p = con.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
            if not p:
                raise ApiError("A product in your cart is no longer available", 409, "unavailable")
            if p["stock"] < qty:
                raise ApiError(f"Only {p['stock']} left of {p['name_en']}", 409, "out_of_stock")
            unit = p["sale_price"] or p["price"]
            subtotal += unit * qty
            items.append((p, unit, qty))
        delivery = int(st["delivery_dhaka" if area == "dhaka" else "delivery_outside"])
        free_min = int(st.get("free_delivery_min") or 0)
        if free_min > 0 and subtotal >= free_min:
            delivery = 0
        total = subtotal + delivery
        if trx and con.execute("SELECT 1 FROM orders WHERE bkash_trx=? AND status!='cancelled'", (trx,)).fetchone():
            raise ApiError("This TrxID was already used on another order", 409, "dup_trx")
        now = int(time.time())
        for _ in range(8):
            order_no = "DK-" + "".join(secrets.choice(ORDER_CHARS) for _ in range(6))
            if not con.execute("SELECT 1 FROM orders WHERE order_no=?", (order_no,)).fetchone():
                break
        pay_status = "pending" if method == "bkash" else "cod"
        cur = con.execute(
            """INSERT INTO orders(order_no,name,phone,address,area,note,subtotal,delivery,total,payment_method,
               bkash_sender,bkash_trx,payment_status,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?)""",
            (order_no, name, phone, address, area, note, subtotal, delivery, total, method, sender, trx,
             pay_status, now, now))
        oid = cur.lastrowid
        for p, unit, qty in items:
            con.execute("INSERT INTO order_items(order_id,product_id,name_en,name_bn,price,qty,image) VALUES(?,?,?,?,?,?,?)",
                        (oid, p["id"], p["name_en"], p["name_bn"], unit, qty, p["image"]))
            con.execute("UPDATE products SET stock=stock-?, updated=? WHERE id=?", (qty, now, p["id"]))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise
    return jr({"order_no": order_no, "subtotal": subtotal, "delivery": delivery, "total": total,
               "payment": method, "payment_status": pay_status, "status": "new"}, 201)


def order_items(con, oid):
    return [dict(r) for r in con.execute(
        "SELECT product_id,name_en,name_bn,price,qty,image FROM order_items WHERE order_id=?", (oid,))]


def api_track(req, con):
    rate_limit("track:" + req.ip, 30, 600)
    d = req.json()
    phone = norm_phone(d.get("phone"))
    o = con.execute("SELECT * FROM orders WHERE order_no=?", (cs(d.get("order_no"), 20).upper(),)).fetchone()
    if not o or not phone or o["phone"] != phone:
        raise ApiError("We could not find an order with those details", 404, "not_found")
    return jr({"order_no": o["order_no"], "status": o["status"], "payment_status": o["payment_status"],
               "payment": o["payment_method"], "subtotal": o["subtotal"], "delivery": o["delivery"],
               "total": o["total"], "created": o["created"], "items": order_items(con, o["id"])})


# ----------------------------------------------------------------------------- admin API
def api_login(req, con):
    rate_limit("login:" + req.ip, 8, 600)
    d = req.json()
    row = con.execute("SELECT * FROM admins WHERE username=?", (cs(d.get("username"), 40),)).fetchone()
    pw = str(d.get("password") or "")
    ok = db.check_password(pw, row["pw_hash"]) if row else db.check_password(pw, db.hash_password("x"))
    if not row or not ok:
        raise ApiError("Wrong username or password", 401, "bad_login")
    token = sign({"u": row["username"], "exp": time.time() + SESSION_SECONDS})
    return jr({"ok": True, "username": row["username"], "must_change": bool(row["must_change"])},
              cookies=[session_cookie(req, token, SESSION_SECONDS)])


def api_logout(req, con):
    return jr({"ok": True}, cookies=[session_cookie(req, "", 0)])


def api_me(req, con):
    u = admin_name(req)
    if not u:
        return jr({"authenticated": False})
    r = con.execute("SELECT must_change FROM admins WHERE username=?", (u,)).fetchone()
    return jr({"authenticated": True, "username": u, "must_change": bool(r and r["must_change"])})


def api_stats(req, con):
    need_admin(req)
    q = lambda sql, *a: con.execute(sql, a).fetchone()[0]
    day = int(time.time()) - int(time.time()) % 86400 - 6 * 3600  # approx. start of day in UTC+6
    low = con.execute("SELECT id,name_en,name_bn,stock FROM products WHERE active=1 AND stock<=3 ORDER BY stock,id LIMIT 8")
    return jr({
        "new_orders": q("SELECT COUNT(*) FROM orders WHERE status='new'"),
        "to_verify": q("SELECT COUNT(*) FROM orders WHERE payment_status='pending' AND status!='cancelled'"),
        "today_orders": q("SELECT COUNT(*) FROM orders WHERE created>=?", day),
        "revenue": q("SELECT COALESCE(SUM(total),0) FROM orders WHERE status!='cancelled' AND (payment_status='paid' OR status='delivered')"),
        "products": q("SELECT COUNT(*) FROM products"),
        "low_stock": [dict(r) for r in low]})


def api_admin_products(req, con):
    need_admin(req)
    return jr({"items": [prod_dict(r, True) for r in con.execute("SELECT * FROM products ORDER BY id DESC")]})


def api_admin_product_save(req, con, pid=None):
    need_admin(req)
    p = read_product(req.json())
    now = int(time.time())
    if pid is None:
        cur = con.execute(
            """INSERT INTO products(name_en,name_bn,desc_en,desc_bn,category_en,category_bn,price,sale_price,stock,
               image,gallery,active,featured,created,updated) VALUES(:name_en,:name_bn,:desc_en,:desc_bn,:category_en,
               :category_bn,:price,:sale_price,:stock,:image,:gallery,:active,:featured,:now,:now)""", {**p, "now": now})
        pid = cur.lastrowid
    else:
        cur = con.execute(
            """UPDATE products SET name_en=:name_en,name_bn=:name_bn,desc_en=:desc_en,desc_bn=:desc_bn,
               category_en=:category_en,category_bn=:category_bn,price=:price,sale_price=:sale_price,stock=:stock,
               image=:image,gallery=:gallery,active=:active,featured=:featured,updated=:now WHERE id=:id""",
            {**p, "now": now, "id": pid})
        if cur.rowcount == 0:
            raise ApiError("Product not found", 404, "not_found")
    return jr(prod_dict(con.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone(), True), 201)


def api_admin_product_delete(req, con, pid):
    need_admin(req)
    con.execute("DELETE FROM products WHERE id=?", (pid,))
    return jr({"ok": True})


MAGIC = ((b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"RIFF", "webp"))


def api_upload(req, con):
    need_admin(req)
    rate_limit("upload:" + req.ip, 60, 600)
    data = req.json().get("data", "")
    if "," in data[:100]:
        data = data.split(",", 1)[1]
    try:
        raw = base64.b64decode(data, validate=True)
    except Exception:
        raise ApiError("Invalid image data", 400, "bad_image")
    if not 100 < len(raw) <= 4 * 1024 * 1024:
        raise ApiError("Image must be under 4 MB", 400, "bad_image")
    ext = next((e for m, e in MAGIC if raw.startswith(m) and (e != "webp" or raw[8:12] == b"WEBP")), None)
    if not ext:
        raise ApiError("Use a JPG, PNG or WebP image", 400, "bad_image")
    os.makedirs(UPLOADS, exist_ok=True)
    name = f"{secrets.token_hex(8)}.{ext}"
    with open(os.path.join(UPLOADS, name), "wb") as f:
        f.write(raw)
    return jr({"url": "/uploads/" + name}, 201)


def order_row(con, o):
    d = dict(o)
    d["items"] = order_items(con, o["id"])
    return d


def api_admin_orders(req, con):
    need_admin(req)
    where, args = [], []
    s = req.q.get("status", "")
    if s == "verify":
        where.append("payment_status='pending' AND status!='cancelled'")
    elif s in ORDER_STATUSES:
        where.append("status=?")
        args.append(s)
    term = req.q.get("q", "").strip()[:40]
    if term:
        where.append("(order_no LIKE ? OR phone LIKE ? OR name LIKE ? OR bkash_trx LIKE ?)")
        args += [f"%{term}%"] * 4
    sql = "SELECT * FROM orders" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT 200"
    return jr({"items": [order_row(con, o) for o in con.execute(sql, args)]})


def api_admin_order_update(req, con, oid):
    need_admin(req)
    d = req.json()
    con.execute("BEGIN IMMEDIATE")
    try:
        o = con.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
        if not o:
            raise ApiError("Order not found", 404, "not_found")
        status = d.get("status", o["status"])
        pay = d.get("payment_status", o["payment_status"])
        if status not in ORDER_STATUSES or pay not in PAYMENT_STATUSES:
            raise ApiError("Invalid status", 400, "bad_status")
        if o["status"] == "cancelled" and status != "cancelled":
            raise ApiError("A cancelled order cannot be reopened. Ask the customer to place a new order.", 409, "cancelled")
        now = int(time.time())
        if status == "cancelled" and o["status"] != "cancelled":
            for it in con.execute("SELECT product_id,qty FROM order_items WHERE order_id=?", (oid,)):
                con.execute("UPDATE products SET stock=stock+?, updated=? WHERE id=?", (it["qty"], now, it["product_id"]))
        if status == "delivered" and o["payment_method"] == "cod" and pay == "cod":
            pay = "paid"
        con.execute("UPDATE orders SET status=?, payment_status=?, updated=? WHERE id=?", (status, pay, now, oid))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise
    return jr(order_row(con, con.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()))


TEXT_SETTINGS = ("shop_name_en", "shop_name_bn", "tagline_en", "tagline_bn", "announcement_en", "announcement_bn",
                 "address_en", "address_bn", "email", "bkash_account_type")


def api_admin_settings_get(req, con):
    need_admin(req)
    return jr({k: v for k, v in db.get_settings(con).items() if k != "seeded"})


def api_admin_settings_put(req, con):
    need_admin(req)
    d = req.json()
    out = {}
    for k in TEXT_SETTINGS:
        if k in d:
            out[k] = cs(d[k], 160)
    for k in ("delivery_dhaka", "delivery_outside", "free_delivery_min"):
        if k in d:
            out[k] = str(to_int(d[k], k, 0, 100000))
    if "whatsapp" in d:
        p = norm_phone(d["whatsapp"])
        if not p:
            raise ApiError("Enter a valid WhatsApp number", 400, "bad_phone")
        out["whatsapp"] = "88" + p
    if "bkash_number" in d:
        p = norm_phone(d["bkash_number"])
        if not p:
            raise ApiError("Enter a valid bKash number", 400, "bad_phone")
        out["bkash_number"] = p
    for k in ("bkash_enabled", "cod_enabled"):
        if k in d:
            out[k] = "1" if d[k] else "0"
    if out.get("bkash_enabled") == "0" and (out.get("cod_enabled") or db.get_settings(con)["cod_enabled"]) == "0":
        raise ApiError("Keep at least one payment method on", 400, "bad_payment")
    for k, v in out.items():
        con.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
    return api_admin_settings_get(req, con)


def api_password(req, con):
    u = need_admin(req)
    d = req.json()
    row = con.execute("SELECT * FROM admins WHERE username=?", (u,)).fetchone()
    if not db.check_password(str(d.get("current") or ""), row["pw_hash"]):
        raise ApiError("Current password is wrong", 400, "bad_login")
    new = str(d.get("new") or "")
    if len(new) < 8:
        raise ApiError("New password must be at least 8 characters", 400, "weak_password")
    con.execute("UPDATE admins SET pw_hash=?, must_change=0 WHERE username=?", (db.hash_password(new), u))
    return jr({"ok": True})


ROUTES = [
    ("GET", r"/api/settings", api_settings),
    ("GET", r"/api/products", api_products),
    ("GET", r"/api/products/(\d+)", api_product),
    ("POST", r"/api/orders", api_create_order),
    ("POST", r"/api/orders/track", api_track),
    ("POST", r"/api/admin/login", api_login),
    ("POST", r"/api/admin/logout", api_logout),
    ("GET", r"/api/admin/me", api_me),
    ("GET", r"/api/admin/stats", api_stats),
    ("GET", r"/api/admin/products", api_admin_products),
    ("POST", r"/api/admin/products", api_admin_product_save),
    ("PUT", r"/api/admin/products/(\d+)", api_admin_product_save),
    ("DELETE", r"/api/admin/products/(\d+)", api_admin_product_delete),
    ("POST", r"/api/admin/upload", api_upload),
    ("GET", r"/api/admin/orders", api_admin_orders),
    ("PUT", r"/api/admin/orders/(\d+)", api_admin_order_update),
    ("GET", r"/api/admin/settings", api_admin_settings_get),
    ("PUT", r"/api/admin/settings", api_admin_settings_put),
    ("POST", r"/api/admin/password", api_password),
]


def handle_api(req):
    for method, pattern, fn in ROUTES:
        m = re.fullmatch(pattern, req.path)
        if m:
            if method != req.method:
                continue
            con = db.connect()
            try:
                args = [int(g) for g in m.groups()]
                return fn(req, con, *args)
            finally:
                con.close()
    if any(re.fullmatch(p, req.path) for _, p, _ in ROUTES):
        raise ApiError("Method not allowed", 405, "method")
    raise ApiError("Not found", 404, "not_found")


# ----------------------------------------------------------------------------- static files
def file_response(req, path, cache):
    try:
        st = os.stat(path)
    except OSError:
        return None
    etag = f'"{int(st.st_mtime)}-{st.st_size}"'
    ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
    if ctype.startswith("text/") or ctype in ("application/javascript", "application/json", "image/svg+xml"):
        ctype += "; charset=utf-8"
    headers = [("Content-Type", ctype), ("ETag", etag), ("Cache-Control", cache)]
    if path.endswith((".html",)):
        headers.append(("Content-Security-Policy", CSP))
        headers.append(("X-Frame-Options", "DENY"))
    if req.env.get("HTTP_IF_NONE_MATCH") == etag:
        return 304, headers, b""
    with open(path, "rb") as f:
        return 200, headers, f.read()


def safe_join(root, rel):
    full = os.path.realpath(os.path.join(root, rel))
    return full if full.startswith(os.path.realpath(root) + os.sep) else None


def dynamic_text(req, kind):
    base = os.environ.get("DOKAN_BASE_URL") or f"{'https' if req.secure else 'http'}://{req.env.get('HTTP_HOST', 'localhost')}"
    if kind == "robots":
        body = f"User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\n\nSitemap: {base}/sitemap.xml\n"
        return 200, [("Content-Type", "text/plain; charset=utf-8")], body.encode()
    body = (f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"<url><loc>{base}/</loc></url></urlset>\n")
    return 200, [("Content-Type", "application/xml; charset=utf-8")], body.encode()


def handle_static(req):
    p = req.path
    if p == "/":
        return file_response(req, os.path.join(STATIC, "index.html"), "no-cache")
    if p == "/admin":
        return file_response(req, os.path.join(STATIC, "admin.html"), "no-cache")
    if p == "/robots.txt":
        return dynamic_text(req, "robots")
    if p == "/sitemap.xml":
        return dynamic_text(req, "sitemap")
    if p == "/healthz":
        return 200, [("Content-Type", "text/plain")], b"ok"
    if p == "/favicon.ico":
        return file_response(req, os.path.join(STATIC, "img", "favicon.svg"), "public, max-age=86400")
    if p.startswith("/static/"):
        full = safe_join(STATIC, p[len("/static/"):])
        return file_response(req, full, "public, max-age=3600") if full else None
    if p.startswith("/uploads/"):
        full = safe_join(UPLOADS, p[len("/uploads/"):])
        return file_response(req, full, "public, max-age=86400") if full else None
    return None


def application(env, start_response):
    req = Req(env)
    try:
        if req.path.startswith("/api/"):
            status, headers, body = handle_api(req)
        else:
            res = handle_static(req) if req.method in ("GET", "HEAD") else None
            if res is None:
                res = file_response(req, os.path.join(STATIC, "404.html"), "no-cache")
                status, headers, body = (404, res[1], res[2]) if res else (404, [("Content-Type", "text/plain")], b"Not found")
            else:
                status, headers, body = res
    except ApiError as e:
        status, headers, body = jr({"error": e.message, "code": e.code}, e.status)
    except Exception as e:  # never leak internals
        print("ERROR", repr(e))
        status, headers, body = jr({"error": "Something went wrong. Please try again.", "code": "server"}, 500)
    headers = list(headers) + [("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin")]
    reason = {200: "OK", 201: "Created", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
              405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
              429: "Too Many Requests", 500: "Internal Server Error"}.get(status, "OK")
    headers.append(("Content-Length", str(len(body))))
    start_response(f"{status} {reason}", headers)
    return [b"" if req.method == "HEAD" else body]


if __name__ == "__main__":
    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

    class Threaded(ThreadingMixIn, WSGIServer):
        daemon_threads = True

    class Quiet(WSGIRequestHandler):
        def log_message(self, *a):
            pass

    port = int(os.environ.get("PORT", 8000))
    print(f"Dokan running on http://localhost:{port}   (admin: http://localhost:{port}/admin)")
    make_server("0.0.0.0", port, application, server_class=Threaded, handler_class=Quiet).serve_forever()
