# Dokan | দোকান

A complete small online shop for selling physical products in Bangladesh.
Python backend (no packages to install), SQLite database, English and Bangla storefront, admin panel, bKash and cash on delivery.

## What you get

**Storefront** (`/`): home page, product search, categories, sorting, product pages with photo gallery, cart, checkout, order confirmation, order tracking, FAQ, policy pages, floating WhatsApp button, English / বাংলা switch (Bengali digits too). Works on phones and computers.

**Admin panel** (`/admin`): dashboard, orders (verify bKash payment, confirm, ship, deliver, cancel), products (add, edit, hide, delete, upload photos, set sale price and stock at any time), settings (shop name, banner, WhatsApp, bKash number, delivery charges, free delivery limit), password change.

## Run it on your computer

```
python3 app.py
```
Open http://localhost:8000 (shop) and http://localhost:8000/admin (admin).
The first time, the admin password is printed in the terminal and saved in `data/ADMIN_PASSWORD.txt`. Log in as `admin` and change it in Settings.
Needs Python 3.9 or newer. Nothing else.

Run the automatic checks: `python3 tests/smoke_test.py`

## Put it online (PythonAnywhere, free plan works to start)

1. Create an account at pythonanywhere.com.
2. Files tab: upload `dokan.zip`. Open a Bash console and run `unzip dokan.zip`.
3. Web tab: Add a new web app, choose **Manual configuration**, pick Python 3.10 or newer.
4. Open the WSGI configuration file and replace everything with:
   ```
   import os, sys
   sys.path.insert(0, "/home/YOUR_USERNAME/dokan")
   os.environ["DOKAN_ADMIN_PASSWORD"] = "choose-a-long-password"
   os.environ["DOKAN_BASE_URL"] = "https://YOUR_USERNAME.pythonanywhere.com"
   from wsgi import application
   ```
5. Press **Reload**. Your shop is live with HTTPS at `https://YOUR_USERNAME.pythonanywhere.com`.

Any other host that runs WSGI apps works too (`wsgi:application`), for example a VPS with gunicorn.
Back up the `data` folder regularly: it holds the database (`shop.db`) and uploaded photos.

## How bKash payment works here

This shop uses **Send Money**, because a personal bKash account has no payment gateway or API.

1. At checkout the customer sees your bKash number and the exact amount.
2. They send the money in their bKash app, then type their bKash number and the **TrxID**.
3. The order appears in Admin with "Check bKash payment". Open your bKash app, find that TrxID, check the amount, then press **Payment received**.

Safeguards built in: the TrxID format is checked, one TrxID cannot be used on two orders, and totals are calculated on the server so customers cannot change prices.
**Never ship before you have seen the money in your bKash app.** A customer can type any TrxID, and the shop cannot check it for you.
To make this automatic you would need a bKash Merchant account with Payment Gateway access, then add the API. Also check bKash's rules and limits for using a personal account to receive business payments.

## Dummy products

The five sample products and their illustrations are placeholders. Edit or delete them in Admin, and upload your real photos. Replace the sample descriptions with true details about what you sell.

## Settings through environment variables (optional)

`DOKAN_ADMIN_PASSWORD`, `DOKAN_BASE_URL` (used in sitemap.xml), `DOKAN_DATA` (where data is stored), `PORT`.

## Files

```
app.py        backend: API, orders, admin, uploads, static files
db.py         database schema and sample data
wsgi.py       entry point for hosting
static/       storefront, admin panel, styles, scripts, product images
tests/        automatic API checks
data/         created on first run (database, photos, secret key)
```
