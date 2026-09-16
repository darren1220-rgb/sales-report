#!/usr/bin/env python3
"""黑珍珠業務日報 — 資料加密／合併工具（在 repo 根目錄執行；帳號密碼放環境變數 SR_USER / SR_PASS）

  python3 tools/sync.py encrypt data.json     # 整份歷史資料 → data.enc.json（只做一次）
  python3 tools/sync.py decrypt <enc.json>    # 解密任一加密檔，輸出 JSON
  python3 tools/sync.py add today.json        # 合併當日回報 → data/<C|S>-YYYY-MM.enc.json + manifest.json
      today.json：{"中區": {"2026-09-17": [visit, ...]}, "南區": {...}}

網站讀 manifest.json 列出的所有檔案，同一區域同一月份以後面的檔案為準，
所以每天只要重寫當月的小檔案，不用動 data.enc.json。
"""
import base64, gzip, json, os, sys, datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 200000
REPS = {"中區": "明仁", "南區": "Jerry"}
CODE = {"中區": "C", "南區": "S"}

def now():
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")

def cred():
    u, p = os.environ.get("SR_USER"), os.environ.get("SR_PASS")
    if not u or not p:
        sys.exit("請設定環境變數 SR_USER 與 SR_PASS")
    return u, p

def key(salt):
    u, p = cred()
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(f"{u}:{p}".encode())

def decrypt(path):
    f = json.load(open(path))
    salt, iv, ct = (base64.b64decode(f[k]) for k in ("salt", "iv", "ct"))
    return json.loads(gzip.decompress(AESGCM(key(salt)).decrypt(iv, ct, None)))

def encrypt(data, path):
    salt, iv = os.urandom(16), os.urandom(12)
    raw = gzip.compress(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(), 9)
    ct = AESGCM(key(salt)).encrypt(iv, raw, None)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    json.dump({"v": 1, "kdf": "pbkdf2-sha256", "iter": ITER,
               "salt": base64.b64encode(salt).decode(), "iv": base64.b64encode(iv).decode(),
               "ct": base64.b64encode(ct).decode()}, open(path, "w"))
    print(f"寫入 {path}：{os.path.getsize(path)} bytes")

def load_manifest():
    if os.path.exists("manifest.json"):
        return json.load(open("manifest.json"))
    return {"files": ["data.enc.json"], "updatedAt": ""}

def month_base(region, mon, archive):
    """該區域該月份目前的資料：優先 data/ 月檔，其次 data.enc.json 封存"""
    p = f"data/{CODE[region]}-{mon}.enc.json"
    if os.path.exists(p):
        return decrypt(p)["months"][0], p
    if archive is None and os.path.exists("data.enc.json"):
        archive = decrypt("data.enc.json")
    for m in (archive or {}).get("months", []):
        if m["region"] == region and m["month"] == mon:
            return {**m, "days": dict(m["days"])}, p
    return {"region": region, "month": mon, "rep": REPS.get(region, ""), "days": {}}, p

def add(path):
    today = json.load(open(path))
    man = load_manifest(); archive = None; n = 0; written = []
    for region, days in today.items():
        for day, visits in days.items():
            mon = day[:7]
            m, p = month_base(region, mon, archive)
            m["days"][day] = visits; n += len(visits)
            encrypt({"months": [m]}, p); written.append(p)
            if p not in man["files"]:
                man["files"].append(p)
    man["updatedAt"] = now()
    json.dump(man, open("manifest.json", "w"), ensure_ascii=False)
    print(f"合併 {n} 筆拜訪；更新 {sorted(set(written))} 與 manifest.json")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "encrypt":
        encrypt(json.load(open(sys.argv[2])), "data.enc.json")
        man = load_manifest(); man["updatedAt"] = now()
        json.dump(man, open("manifest.json", "w"), ensure_ascii=False)
    elif cmd == "decrypt":
        print(json.dumps(decrypt(sys.argv[2]), ensure_ascii=False))
    elif cmd == "add":
        add(sys.argv[2])
    else:
        sys.exit(__doc__)
