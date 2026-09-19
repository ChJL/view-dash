"""
Pulls holdings from a Google Sheet using a service account, encrypts the
result with AES-256-GCM (key derived from DASHBOARD_PASSWORD via PBKDF2),
and writes data.json in the repo root. The ciphertext format is compatible
with the Web Crypto decryption done in index.html — raw holdings data is
never written to disk or to the repo in plaintext.

Required environment variables:
  GOOGLE_SERVICE_ACCOUNT_JSON  - full JSON key of a Google service account
                                  (stored as a GitHub Actions secret)
  SHEET_ID                     - the spreadsheet ID (from its URL)
  DASHBOARD_PASSWORD           - the same password used to log into the
                                  dashboard (stored as a GitHub Actions secret)
Optional:
  SHEET_RANGE                  - defaults to "A1:Z1000" (first visible tab).
                                  Prefix with a tab name to target a specific
                                  tab, e.g. "Holdings!A1:Z1000".

Expected sheet columns (any order, matched by header text):
  ticker, shares, avg_cost, account, sector, total_cost, now_per_share, now_value
"""
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.oauth2 import service_account
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']
PBKDF2_ITERATIONS = 200000


def normalize_header(h):
    return (h or '').strip().lower().replace(' ', '').replace('_', '')


def find_col(headers, names):
    for i, h in enumerate(headers):
        if h in names:
            return i
    return -1


def get_cell(row, i):
    if i < 0 or i >= len(row):
        return None
    return row[i]


def to_float(v, default=0.0):
    if v is None or v == '':
        return default
    try:
        return float(str(v).replace(',', '').replace('$', ''))
    except ValueError:
        return default


def encrypt_payload(password, payload):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS, dklen=32)
    iv = os.urandom(12)
    plaintext = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return {
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'iterations': PBKDF2_ITERATIONS,
        'ciphertext': base64.b64encode(ciphertext).decode(),
    }


def fetch_holdings():
    creds_json = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON')
    sheet_id = os.environ.get('VIEWDASH_SHEET_ID')
    sheet_range = os.environ.get('SHEET_RANGE', 'A1:Z1000')

    if not creds_json or not sheet_id:
        print('Missing GOOGLE_SERVICE_ACCOUNT_JSON or SHEET_ID', file=sys.stderr)
        sys.exit(1)

    creds_info = json.loads(creds_json)
    creds = service_account.Credentials.from_service_account_info(creds_info, scopes=SCOPES)
    service = build('sheets', 'v4', credentials=creds)

    result = service.spreadsheets().values().get(
        spreadsheetId=sheet_id, range=sheet_range
    ).execute()
    values = result.get('values', [])
    if not values:
        return []

    headers = [normalize_header(h) for h in values[0]]
    rows = values[1:]

    idx = {
        'ticker': find_col(headers, ['ticker', 'symbol']),
        'shares': find_col(headers, ['shares', 'qty', 'quantity']),
        'avg_cost': find_col(headers, ['avgcost', 'averagecost', 'cost']),
        'account': find_col(headers, ['account']),
        'sector': find_col(headers, ['sector']),
        'total_cost': find_col(headers, ['totalcost']),
        'now_per_share': find_col(headers, ['nowpershare', 'currentprice', 'price']),
        'now_value': find_col(headers, ['nowvalue', 'marketvalue', 'value']),
    }

    holdings = []
    for row in rows:
        ticker = get_cell(row, idx['ticker'])
        if not ticker:
            continue
        shares = to_float(get_cell(row, idx['shares']))
        avg_cost = to_float(get_cell(row, idx['avg_cost']))
        total_cost = to_float(get_cell(row, idx['total_cost'])) or (shares * avg_cost)
        now_per_share = to_float(get_cell(row, idx['now_per_share'])) or avg_cost
        now_value = to_float(get_cell(row, idx['now_value'])) or (shares * now_per_share)
        holdings.append({
            'ticker': str(ticker).strip().upper(),
            'shares': shares,
            'avgCost': avg_cost,
            'account': (get_cell(row, idx['account']) or '未分類帳戶').strip(),
            'sector': (get_cell(row, idx['sector']) or '未分類').strip(),
            'totalCost': total_cost,
            'nowPerShare': now_per_share,
            'nowValue': now_value,
        })
    return holdings


def main():
    dashboard_password = os.environ.get('DASHBOARD_PASS')
    if not dashboard_password:
        print('Missing DASHBOARD_PASSWORD', file=sys.stderr)
        sys.exit(1)

    holdings = fetch_holdings()
    encrypted = encrypt_payload(dashboard_password, {'holdings': holdings})

    output = {
        'updatedAt': datetime.now(timezone.utc).isoformat(),
        **encrypted,
    }

    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f'Wrote {len(holdings)} holdings to data.json (encrypted)')


if __name__ == '__main__':
    main()

