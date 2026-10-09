#!/usr/bin/env bash
# =====================================================================
# run_attacks.sh - Rejoue les 5 scenarios d'intrusion contre 127.0.0.1
# Prerequis : Snort en ecoute (sudo snort -A fast -k none -c ... -i lo -l /var/log/snort)
#             Apache2 demarre, serveur SSH actif.
# Usage : bash scenarios/run_attacks.sh
# =====================================================================
TARGET="127.0.0.1"
echo "### Cible : $TARGET ###"
pause() { echo; read -rp ">> Entree pour le scenario suivant..."; echo; }

echo "=== Scenario 1 : Scan de ports Xmas ==="
sudo nmap -sX "$TARGET"
pause

echo "=== Scenario 2 : Force brute SSH ==="
for i in $(seq 1 6); do
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=2 baduser@"$TARGET" exit 2>/dev/null
  echo "  tentative $i"
done
pause

echo "=== Scenario 3 : Scanner web (Nikto User-Agent) ==="
curl -s -A "Nikto/2.5.0" "http://$TARGET/" -o /dev/null -w "HTTP %{http_code}\n"
pause

echo "=== Scenario 4 : Anomalie ICMP ==="
sudo ping -s 1500 -c 4 "$TARGET"
pause

echo "=== Scenario 5 : Injection SQL ==="
curl -s "http://$TARGET/?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users" -o /dev/null -w "HTTP %{http_code}\n"

echo; echo "### Termine. Verifier :  sudo grep LOCAL /var/log/snort/alert ###"
