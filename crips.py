#!/usr/bin/env python3
# inline_poller.py
import os
import time
import json
import base64
import logging
import requests
from urllib.parse import urlparse

# ---------- Konfigürasyon ----------
BOT_TOKEN = "PUT_YOUR_BOT_TOKEN_HERE"
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"
POLL_INTERVAL = 1.0  # saniye
PENDING_BANS_FILE = "/sdcard/debug/pending_bans.json"   # Fly.io'da uygun path ayarla
TESPIT_DOSYA = "/sdcard/debug/tespitedilenbenzeradresler.txt"
YASAKLI_KELIMELER_DOSYA = "/sdcard/debug/yasaklikelimeler.txt"
YASAKLI_KATEGORI_DOSYA = "/sdcard/debug/yasaklikategori.txt"
ADMIN_IDS = [6347198684]  # kendi admin id'lerini ekle
# ------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def load_pending_bans():
    try:
        if not os.path.exists(PENDING_BANS_FILE):
            return []
        with open(PENDING_BANS_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or []
    except Exception:
        return []

def save_pending_bans(lst):
    try:
        with open(PENDING_BANS_FILE, "w", encoding="utf-8") as f:
            json.dump(lst, f, ensure_ascii=False, indent=2)
    except Exception:
        logging.exception("pending bans kaydedilemedi")

def add_pending_ban(host, kategori):
    lst = load_pending_bans()
    lst.append({"host": host, "kategori": kategori})
    # uniq by host, keep last
    uniq = {}
    for it in lst:
        uniq[it["host"]] = it
    save_pending_bans(list(uniq.values()))

def process_pending_bans():
    lst = load_pending_bans()
    if not lst:
        return
    # uygulama: burada sadece dosyaya kaydediyoruz (yasaklı kelimeler/kategoriler dosyalarına ekleme)
    for it in lst:
        try:
            h = (it.get("host") or "").strip()
            k = (it.get("kategori") or "").strip()
            if h:
                yasakli_kelime_ekle(h)
            if k:
                yasakli_kategori_ekle(k)
        except Exception:
            logging.exception("pending ban işlenirken hata")
    # temizle
    try:
        os.remove(PENDING_BANS_FILE)
    except Exception:
        save_pending_bans([])

def yasakli_kelime_ekle(host, path=YASAKLI_KELIMELER_DOSYA):
    h = (host or "").strip().lower()
    if not h:
        return
    try:
        existing = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                existing = [ln.strip().lower() for ln in f if ln.strip()]
        if h in existing:
            return
        with open(path, "a", encoding="utf-8") as f:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                f.write("\n" + h)
            else:
                f.write(h)
        logging.info("yasakli kelime eklendi: %s", h)
    except Exception:
        logging.exception("yasakli_kelime_ekle hata")

def yasakli_kategori_ekle(kategori, path=YASAKLI_KATEGORI_DOSYA):
    k = (kategori or "").strip()
    if not k:
        return
    try:
        existing = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                existing = [ln.strip() for ln in f if ln.strip()]
        if k in existing:
            return
        with open(path, "a", encoding="utf-8") as f:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                f.write("\n" + k)
            else:
                f.write(k)
        logging.info("yasakli kategori eklendi: %s", k)
    except Exception:
        logging.exception("yasakli_kategori_ekle hata")

def make_ban_callback_payload(base, kategori=""):
    """
    döndürür: yasakla:host veya yasakla:host|b64(kategori)
    """
    try:
        p = urlparse(base)
        host = p.hostname or (p.netloc.split(":",1)[0] if p.netloc else base)
    except Exception:
        host = str(base).split("//")[-1].split(":")[0].split("/")[0]
    host = (host or "").strip()
    enc = ""
    if kategori:
        try:
            enc = base64.urlsafe_b64encode(kategori.encode("utf-8")).decode("ascii")
        except Exception:
            enc = ""
    if enc:
        return f"yasakla:{host}|{enc}"
    return f"yasakla:{host}"

def make_showgroup_callback_payload(group_key):
    try:
        enc = base64.urlsafe_b64encode(str(group_key).encode("utf-8")).decode("ascii")
        return f"showgroup:{enc}"
    except Exception:
        return f"showgroup:{group_key}"

def load_tespit_edilen_gruplar(path=TESPIT_DOSYA):
    groups = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            current = None
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                if ln.lower().startswith("gurup"):
                    current = ln
                    groups.setdefault(current, [])
                else:
                    if current is not None:
                        groups[current].append(ln)
    except FileNotFoundError:
        pass
    return groups

def answer_callback(callback_query_id, text, show_alert=False):
    try:
        requests.post(API_BASE + "/answerCallbackQuery", json={
            "callback_query_id": callback_query_id,
            "text": text,
            "show_alert": bool(show_alert)
        }, timeout=5)
    except Exception:
        logging.exception("answerCallbackQuery hata")

def send_private_message(user_id, text):
    try:
        requests.post(API_BASE + "/sendMessage", json={"chat_id": user_id, "text": text}, timeout=5)
    except Exception:
        logging.exception("private message gönderilemedi")

def start_bot_poller(poll_interval=POLL_INTERVAL):
    logging.info("Inline poller başlatılıyor...")
    process_pending_bans()  # başlangıçta bekleyenleri uygula
    offset = None
    while True:
        try:
            params = {"timeout": 30, "limit": 50}
            if offset:
                params["offset"] = offset
            r = requests.get(API_BASE + "/getUpdates", params=params, timeout=40)
            data = r.json() if r is not None else {}
            if not data.get("ok"):
                time.sleep(poll_interval)
                continue
            updates = data.get("result", [])
            for upd in updates:
                try:
                    offset = max(offset or 0, upd.get("update_id", 0) + 1)
                except Exception:
                    offset = (upd.get("update_id") or 0) + 1
                cq = upd.get("callback_query")
                if not cq:
                    continue
                cb = (cq.get("data") or "") or ""
                from_user = cq.get("from") or {}
                from_id = from_user.get("id")
                cq_id = cq.get("id")
                message = cq.get("message") or {}
                msg_chat = (message.get("chat") or {})
                msg_chat_id = msg_chat.get("id")
                msg_message_id = message.get("message_id")
                # handle showgroup:
                if cb.startswith("showgroup:"):
                    payload = cb[len("showgroup:"):]
                    try:
                        group_key = base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8")
                    except Exception:
                        group_key = payload
                    groups = load_tespit_edilen_gruplar()
                    lst = groups.get(group_key) or []
                    if not lst:
                        answer_callback(cq_id, "Tespit edilen adres bulunamadı.", show_alert=True)
                    else:
                        text_preview = "\n".join(lst[:30])
                        if len("\n".join(lst)) > 2000 or len(lst) > 60:
                            answer_callback(cq_id, f"Tespit edilen {len(lst)} adres bulundu. Tam liste özel mesajla gönderildi.", show_alert=True)
                            if from_id:
                                send_private_message(from_id, "Tespit edilen Dns Adresleri:\n" + "\n".join(lst))
                        else:
                            answer_callback(cq_id, "Tespit edilen Dns Adresleri:\n" + text_preview + (f"\n... ve {len(lst)-30} adet daha" if len(lst) > 30 else ""), show_alert=True)
                    continue
                # only handle yasakla:
                if not cb.startswith("yasakla:"):
                    continue
                try:
                    payload = cb[len("yasakla:"):]
                    parts = payload.split("|")
                    base = parts[0] if len(parts) > 0 else ""
                    enc_kategori = parts[1] if len(parts) > 1 else ""
                    kategori = ""
                    if enc_kategori:
                        try:
                            kategori = base64.urlsafe_b64decode(enc_kategori.encode("ascii")).decode("utf-8")
                        except Exception:
                            kategori = enc_kategori
                    # permission check: chat admin or global admin
                    allowed = False
                    try:
                        if msg_chat_id and from_id is not None:
                            cm = requests.get(API_BASE + "/getChatMember", params={"chat_id": msg_chat_id, "user_id": from_id}, timeout=5)
                            cmj = cm.json() if cm is not None else {}
                            if cmj.get("ok"):
                                res = cmj.get("result", {})
                                status = res.get("status", "")
                                if status in ("administrator", "creator"):
                                    allowed = True
                    except Exception:
                        allowed = False
                    if not allowed and from_id is not None and from_id in ADMIN_IDS:
                        allowed = True
                    if not allowed:
                        answer_callback(cq_id, "Bu işlemi sadece grup yöneticileri gerçekleştirebilir.", show_alert=True)
                        continue
                    # extract hostname only
                    try:
                        p = urlparse(base)
                        hostname_only = p.hostname or ""
                        if hostname_only:
                            to_add = hostname_only.strip().lower()
                        else:
                            net = p.netloc or base
                            to_add = str(net).split(":", 1)[0].strip().lower()
                    except Exception:
                        to_add = str(base).split("//")[-1].split(":")[0].split("/")[0].strip().lower()
                    # attempt to add ban; on failure add to pending
                    try:
                        if to_add:
                            yasakli_kelime_ekle(to_add)
                        if kategori and kategori.strip():
                            yasakli_kategori_ekle(kategori.strip())
                    except Exception:
                        try:
                            add_pending_ban(to_add, kategori)
                        except Exception:
                            logging.exception("pending ban eklenemedi")
                    # remove inline keyboard from original message
                    try:
                        if msg_chat_id is not None and msg_message_id is not None:
                            requests.post(API_BASE + "/editMessageReplyMarkup", json={
                                "chat_id": msg_chat_id,
                                "message_id": msg_message_id,
                                "reply_markup": {}
                            }, timeout=5)
                    except Exception:
                        logging.exception("editMessageReplyMarkup hata")
                    answer_callback(cq_id, "DNS başarıyla yasaklandı.", show_alert=False)
                except Exception:
                    logging.exception("yasakla callback işlenirken hata")
            # end for updates
        except Exception:
            logging.exception("poller ana döngü hatası")
            time.sleep(max(1.0, poll_interval))
            continue
        time.sleep(poll_interval)

if __name__ == "__main__":
    start_bot_poller()
