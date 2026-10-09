# Moteur de notification

Le script `scripts/notify_snort.py` assure la dernière étape du pipeline SIEM :
dès qu'une intrusion est détectée, l'administrateur est **notifié** avec une
explication (signature, priorité, source, cible, action recommandée).

## Fonctionnement

Le script surveille en continu deux sources :
- `/var/log/snort/alert` — les alertes du moteur de détection Snort,
- `/var/log/auth.log` — les échecs d'authentification SSH (corrélation système).

Pour chaque événement pertinent, il génère une notification formatée, avec un
**anti-spam** (une notification au maximum par signature toutes les 60 s) et un
**seuil** pour la force brute SSH (≥ 3 échecs en 30 s).

## Deux canaux

### 1. Notification locale (par défaut)

Chaque alerte est écrite dans un journal dédié `/var/log/notifications_admin.log`,
horodatée et mise en forme comme un message destiné à l'administrateur. Ce canal
ne dépend d'aucun réseau et fonctionne systématiquement.

### 2. Courriel (optionnel)

En passant `USE_EMAIL = True` et en renseignant le bloc SMTP (Yahoo/Gmail +
**mot de passe d'application**), le script envoie aussi un e-mail.

> **Note sur l'environnement de test :** le canal courriel (SMTP Yahoo, ports
> 587 et 465) a été implémenté et testé, mais les **ports SMTP sortants sont
> bloqués** par la politique réseau de l'environnement (WSL / réseau campus),
> ce qui provoque une erreur `Connection unexpectedly closed`. La notification
> est donc journalisée localement, ce qui démontre le moteur d'alerte de façon
> fiable. En production (ports SMTP ouverts), l'activation de `USE_EMAIL` suffit.

## Utilisation

```bash
# 1. Snort doit ecrire ses alertes en mode fast dans un fichier :
sudo snort -A fast -k none -c /etc/snort/snort.conf -i lo -l /var/log/snort

# 2. Lancer le moteur de notification (autre terminal) :
sudo python3 scripts/notify_snort.py

# 3. Declencher une attaque (autre terminal) :
curl "http://127.0.0.1/?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users"

# 4. Consulter les notifications generees :
sudo cat /var/log/notifications_admin.log
```

## Exemple de notification générée

```
============================================================
[2026-10-09 08:51:55] NOTIFICATION ADMINISTRATEUR
OBJET : [ALERTE SNORT - PRIORITE CRITIQUE] LOCAL SQLi UNION SELECT
------------------------------------------------------------
INTRUSION DETECTEE PAR LE SIEM
------------------------------
Signature : LOCAL SQLi UNION SELECT
SID Snort : 1000005
Priorite  : 1 (CRITIQUE)
Source    : 127.0.0.1:53660
Cible     : 127.0.0.1:80
Detecte le: 2026-10-09 08:51:55

Action : identifier la source, verifier dans Kibana, bloquer si externe.
============================================================
```

## Stratégie de priorisation des alertes

| Scénario | Priorité Snort | Canal / Urgence |
|----------|----------------|-----------------|
| Injection SQL | 1 — Critique | Notification immédiate |
| Nikto | 1 — Critique | Notification immédiate |
| Force brute SSH | Haute (corrélation) | Notification + blocage IP |
| Scan Xmas | 2 — Moyenne | Surveillance |
| ICMP | 2 — Moyenne | Surveillance selon contexte |

Cette priorisation évite la fatigue d'alertes : les menaces critiques (SQLi,
Nikto) déclenchent une notification immédiate, les activités de reconnaissance
(scan, ICMP) sont journalisées pour analyse.
