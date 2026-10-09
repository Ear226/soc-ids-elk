# Installation pas-à-pas

Environnement : **Ubuntu 22.04 (WSL2)**. Toutes les commandes s'exécutent dans le
terminal Ubuntu, avec `sudo`.

> Sous WSL, `systemctl` n'est pas toujours disponible : utiliser `sudo service <nom> start`
> si `systemctl` renvoie « System has not been booted with systemd ».

---

## 1. Préparation du système

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y wget curl jq net-tools
```

## 2. Serveur web cible (Apache2)

Sert de cible aux scénarios web (Nikto, SQLi).

```bash
sudo apt install -y apache2
sudo service apache2 start
curl http://127.0.0.1        # doit renvoyer la page HTML Apache
```

## 3. IDS/IPS — Snort

```bash
sudo apt install -y snort
# Verifier l'installation :
snort -V
```

### Configuration réseau

Éditer `/etc/snort/snort.conf` et définir `HOME_NET` (voir
`config/snort-home-net.txt`). Le loopback est inclus car les attaques de test
visent `127.0.0.1` :

```
ipvar HOME_NET [172.26.160.0/20,127.0.0.1/32]
```

### Règles personnalisées

Copier les 5 règles du projet et les déclarer :

```bash
sudo cp rules/local.rules /etc/snort/rules/local.rules
# Dans snort.conf, verifier la presence de :
#   include $RULE_PATH/local.rules
```

### Validation

```bash
sudo snort -T -c /etc/snort/snort.conf
# Doit afficher : "Snort successfully validated the configuration!"
```

## 4. Collecteur de logs — syslog-ng

```bash
sudo apt install -y syslog-ng
sudo cp config/syslog-ng-projet_elk.conf /etc/syslog-ng/conf.d/projet_elk.conf
sudo syslog-ng -s          # verifie la syntaxe
sudo service syslog-ng restart
# Test :
logger -t snort "Alerte test pour mon projet ELK"
tail -f /var/log/syslog_projet_elk.log   # doit afficher le message
```

## 5. Elasticsearch + Kibana (pile ELK)

```bash
# Depot Elastic
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install -y elasticsearch kibana

sudo service elasticsearch start
sudo service kibana start
curl http://localhost:9200   # verifie Elasticsearch
# Kibana : http://localhost:5601
```

## 6. Expédition — Filebeat

Filebeat lit les fichiers de logs (Snort, auth.log) et les envoie à Elasticsearch.

```bash
sudo apt install -y filebeat
# Activer le module system et configurer les chemins de logs Snort dans
# /etc/filebeat/filebeat.yml (inputs -> /var/log/snort/*, /var/log/auth.log)
sudo filebeat modules enable system
sudo service filebeat start
```

## 7. Moteur de notification

```bash
sudo apt install -y python3
cp scripts/notify_snort.py ~/notify_snort.py
# Configurer en tete du fichier (canal e-mail ou journal local), puis :
sudo python3 ~/notify_snort.py
```

Voir [`NOTIFICATION.md`](NOTIFICATION.md) pour le détail.

---

## Vérification finale

```bash
# Lancer Snort en ecoute + ecriture fichier
sudo snort -A fast -k none -c /etc/snort/snort.conf -i lo -l /var/log/snort
# Dans un autre terminal, rejouer une attaque :
curl "http://127.0.0.1/?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users"
# Verifier la detection :
sudo grep "LOCAL" /var/log/snort/alert
```
