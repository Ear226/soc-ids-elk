#!/usr/bin/env python3
"""
notify_snort.py - Moteur de notification du SIEM.
Surveille les alertes Snort (/var/log/snort/alert) et les echecs SSH
(/var/log/auth.log), puis notifie l'administrateur.

Deux canaux :
  - NOTIFICATION LOCALE (par defaut) : ecrit un message formate dans
    /var/log/notifications_admin.log. Fonctionne sans reseau.
  - E-MAIL (optionnel) : mettre USE_EMAIL = True et renseigner le bloc SMTP.
    NB : de nombreux reseaux (campus, WSL) bloquent les ports SMTP sortants
    (587/465) ; dans ce cas le canal local prend le relais.

Lancement : sudo python3 notify_snort.py
"""
import smtplib, ssl, time, os, re, threading
from email.mime.text import MIMEText
from datetime import datetime
from collections import deque

# ===================== CONFIGURATION =====================
USE_EMAIL = False                 # True pour activer l'envoi e-mail
SMTP_HOST = "smtp.mail.yahoo.com"
SMTP_PORT = 465
SMTP_USER = "ton.adresse@yahoo.com"
SMTP_PASS = "xxxxxxxxxxxxxxxx"     # mot de passe d'application (16 car.)
MAIL_FROM = SMTP_USER
MAIL_TO   = "ton.adresse@yahoo.com"

NOTIF_LOG   = "/var/log/notifications_admin.log"
SNORT_ALERT = "/var/log/snort/alert"
AUTH_LOG    = "/var/log/auth.log"

THROTTLE_SECONDS   = 60     # 1 notif max par signature / 60s (anti-spam)
SSH_FAIL_THRESHOLD = 3      # nb d'echecs SSH avant alerte
SSH_FAIL_WINDOW    = 30     # ...dans cette fenetre (secondes)
# =========================================================

_last_sent, _ssh_fails, _lock = {}, {}, threading.Lock()

def should_send(key):
    now = time.time()
    with _lock:
        if now - _last_sent.get(key, 0) >= THROTTLE_SECONDS:
            _last_sent[key] = now
            return True
    return False

def notify(subject, body):
    """Ecrit la notification dans le journal local, et par e-mail si active."""
    entry = (f"\n{'='*60}\n[{datetime.now():%Y-%m-%d %H:%M:%S}] NOTIFICATION ADMINISTRATEUR\n"
             f"OBJET : {subject}\n{'-'*60}\n{body}{'='*60}\n")
    try:
        with open(NOTIF_LOG, "a") as f:
            f.write(entry)
        print(f"[+] NOTIFICATION envoyee -> {NOTIF_LOG}")
        print(f"    >>> {subject}")
    except Exception as e:
        print(f"[!] Echec ecriture notification : {e}")

    if USE_EMAIL:
        try:
            msg = MIMEText(body); msg["Subject"] = subject
            msg["From"] = MAIL_FROM; msg["To"] = MAIL_TO
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=ctx) as s:
                s.login(SMTP_USER, SMTP_PASS); s.send_message(msg)
            print(f"[+] E-mail envoye : {subject}")
        except Exception as e:
            print(f"[!] Echec envoi e-mail : {e}")

# --- Analyse des alertes Snort (format -A fast) ----------------------
SNORT_RE = re.compile(
    r"\[\*\*\]\s\[\d+:(?P<sid>\d+):\d+\]\s(?P<msg>.*?)\s\[\*\*\]"
    r".*?\[Priority:\s(?P<prio>\d+)\]"
    r"(?:.*?\}\s(?P<src>\S+)\s->\s(?P<dst>\S+))?")
PRIO = {"1": "CRITIQUE", "2": "MOYENNE", "3": "FAIBLE"}

def handle_snort_line(line):
    if "LOCAL" not in line: return
    m = SNORT_RE.search(line)
    if not m: return
    sid, sig, prio = m.group("sid"), m.group("msg"), m.group("prio")
    src, dst = m.group("src") or "?", m.group("dst") or "?"
    if not should_send(("snort", sid)): return
    label = PRIO.get(prio, prio)
    notify(
        f"[ALERTE SNORT - PRIORITE {label}] {sig}",
        "INTRUSION DETECTEE PAR LE SIEM\n------------------------------\n"
        f"Signature : {sig}\nSID Snort : {sid}\nPriorite  : {prio} ({label})\n"
        f"Source    : {src}\nCible     : {dst}\n"
        f"Detecte le: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n"
        "Action : identifier la source, verifier dans Kibana, bloquer si externe.\n")

# --- Analyse des echecs SSH (auth.log) -------------------------------
AUTH_RE = re.compile(r"(?:Failed password for|Invalid user).*?from (?P<ip>\d+\.\d+\.\d+\.\d+)")

def handle_auth_line(line):
    m = AUTH_RE.search(line)
    if not m: return
    ip, now = m.group("ip"), time.time()
    with _lock:
        dq = _ssh_fails.setdefault(ip, deque()); dq.append(now)
        while dq and now - dq[0] > SSH_FAIL_WINDOW: dq.popleft()
        count = len(dq)
    if count < SSH_FAIL_THRESHOLD or not should_send(("ssh", ip)): return
    notify(
        f"[ALERTE SSH - PRIORITE HAUTE] Force brute depuis {ip}",
        "ATTAQUE PAR FORCE BRUTE SSH DETECTEE\n------------------------------------\n"
        f"Source     : {ip}\nEchecs     : {count} tentatives en < {SSH_FAIL_WINDOW}s\n"
        f"Detecte le : {datetime.now():%Y-%m-%d %H:%M:%S}\n\n"
        "Action : bannir l'IP (fail2ban/iptables), verifier aucune connexion reussie.\n")

def follow(path, handler):
    while not os.path.exists(path):
        print(f"[i] En attente de {path} ..."); time.sleep(2)
    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END); print(f"[i] Surveillance de {path}")
        while True:
            line = f.readline()
            if not line: time.sleep(0.3); continue
            handler(line)

def main():
    print("=== notify_snort demarre ===")
    print(f"[i] Canal e-mail : {'ACTIF' if USE_EMAIL else 'DESACTIVE (journal local)'}")
    for path, h in [(SNORT_ALERT, handle_snort_line), (AUTH_LOG, handle_auth_line)]:
        threading.Thread(target=follow, args=(path, h), daemon=True).start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[i] Arret.")

if __name__ == "__main__":
    main()
