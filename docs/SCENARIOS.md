# Les 5 scénarios d'intrusion

Les attaques sont lancées en local contre `127.0.0.1`. Snort écoute sur le
loopback (`-i lo`) avec l'option `-k none` (les paquets du loopback ont des
checksums que Snort rejetterait autrement).

**Prérequis :** Apache2 démarré (cible web sur :80), serveur SSH actif (scénario 2).
**Lancer Snort :** `sudo snort -A fast -k none -c /etc/snort/snort.conf -i lo -l /var/log/snort`

---

## Scénario 1 — Scan de ports (Xmas Scan)

- **Menace :** reconnaissance. L'attaquant cartographie les ports ouverts en envoyant des paquets aux drapeaux FIN+PSH+URG activés simultanément, pour contourner les pare-feux sans état. Phase 1 de la Cyber Kill Chain (OSI couches 3-4).
- **Commande :** `sudo nmap -sX 127.0.0.1`
- **Règle (SID 1000001) :** détecte les paquets TCP avec `flags:FPU`.
- **Détection observée :** `[1:1000001:1] LOCAL Xmas scan detecte` (une alerte par port scanné).
- **Logs prioritaires :** alertes Snort — priorité moyenne (reconnaissance interne suspecte).

## Scénario 2 — Force brute SSH

- **Menace :** compromission d'accès par tentatives répétées d'authentification SSH (OSI couche système). Si réussie → shell distant, pivot, rançongiciel.
- **Commande :** `for i in $(seq 1 6); do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=2 baduser@127.0.0.1 exit 2>/dev/null; done`
- **Double détection :**
  - Réseau (SID 1000002) : ≥ 5 connexions SYN vers le port 22 en 30 s.
  - Système : `/var/log/auth.log` enregistre `Invalid user baduser` / `Failed password`.
- **Logs prioritaires :** corrélation réseau (Snort) + système (auth.log) — priorité haute.
- **Intérêt :** illustre la **corrélation de logs hybrides**, point central d'un SIEM.

## Scénario 3 — Scanner web (User-Agent Nikto)

- **Menace :** recherche automatisée de vulnérabilités web (répertoires cachés, scripts obsolètes). OSI couche 7, inspection de paquets en profondeur (DPI).
- **Commande :** `curl -A "Nikto/2.5.0" http://127.0.0.1/`
- **Règle (SID 1000003) :** détecte la chaîne `Nikto` dans le contenu de la requête HTTP.
- **Détection observée :** `[1:1000003:2] LOCAL Nikto User-Agent` — priorité 1 (critique).
- **Logs prioritaires :** alertes Snort applicatives + logs d'accès Apache.

## Scénario 4 — Anomalie ICMP

- **Menace :** le protocole ICMP peut être détourné (ping flood, tunneling / exfiltration de données dans des paquets ICMP). Peu surveillé, donc prisé pour contourner les pare-feux.
- **Commande :** `sudo ping -s 1500 -c 4 127.0.0.1`
- **Règle (SID 1000004) :** détecte tout echo-request ICMP (`itype:8`). Le serveur n'ayant aucune raison légitime de recevoir des pings, toute requête est traitée comme anomalie.
- **Détection observée :** `[1:1000004:4] LOCAL ICMP detecte` (une alerte par ping).
- **Logs prioritaires :** alertes Snort ICMP — priorité moyenne selon le contexte.

## Scénario 5 — Injection SQL (SQLi)

- **Menace :** exfiltration / altération de la base via une requête web malveillante. Sommet de l'OWASP Top 10. Menace l'intégrité et la confidentialité des données.
- **Commande :** `curl "http://127.0.0.1/?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users"`
- **Règle (SID 1000005) :** détecte les motifs `UNION` + `SELECT` dans la requête HTTP.
- **Détection observée :** `[1:1000005:2] LOCAL SQLi UNION SELECT` — priorité 1 (critique).
- **Logs prioritaires :** alertes Snort — priorité critique, notification immédiate à l'admin.

---

## Vérification des détections

```bash
# N'afficher que les detections du projet :
sudo grep "LOCAL" /var/log/snort/alert

# Ou en direct dans la console :
sudo snort -A console -q -k none -c /etc/snort/snort.conf -i lo 2>/dev/null | grep "LOCAL"
```

## Justification globale des choix

Les 5 scénarios suivent une logique de **défense en profondeur** couvrant les
phases de la Cyber Kill Chain (reconnaissance → accès → exploitation → exfiltration)
et plusieurs couches du modèle OSI (3-4 réseau, 7 applicatif, système). Ils
illustrent les trois piliers CIA : confidentialité (SSH, SQLi), intégrité (SQLi),
disponibilité (ICMP flood).

| # | Scénario | Phase Kill Chain | Couche OSI | Pilier CIA |
|---|----------|------------------|------------|------------|
| 1 | Scan Xmas | Reconnaissance | 3-4 | — (préparatoire) |
| 2 | Force brute SSH | Accès | Système | Confidentialité |
| 3 | Nikto | Reconnaissance applicative | 7 | — (préparatoire) |
| 4 | ICMP | Exfiltration / DoS | 3 | Disponibilité |
| 5 | SQLi | Exploitation | 7 | Confidentialité + Intégrité |
