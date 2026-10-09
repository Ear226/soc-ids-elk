# Visualisation dans Kibana

Accès : `http://localhost:5601`

## 1. Créer la Data View

**Menu ☰ → Stack Management → Data Views → Create data view.**

Les logs de Snort et du système sont expédiés par Filebeat vers Elasticsearch
(index `filebeat-*`). Créer une Data View :

| Nom | Index pattern | Champ temporel |
|-----|---------------|----------------|
| Logs SIEM | `filebeat-*` | `@timestamp` |

## 2. Explorer les alertes (Discover)

**Menu ☰ → Analytics → Discover.**

Filtres KQL utiles pour isoler chaque scénario :

- Toutes les détections du projet : `message : *LOCAL*`
- Scan Xmas : `message : *Xmas*`
- Nikto : `message : *Nikto*`
- SQLi : `message : *UNION*`
- ICMP : `message : *ICMP*`
- Force brute SSH : `message : *Failed password*` ou `message : *Invalid user*`

Faire **une capture par scénario** (section « Visualisation » du barème).

## 3. Dashboard (bonus)

**Menu ☰ → Analytics → Dashboard → Create.** Construire 4 panneaux :

1. **Alertes dans le temps** — histogramme (date histogram sur `@timestamp`),
   réparti par signature. Le scan Xmas et l'ICMP produisent des pics nets.
2. **Top des signatures** — table ou camembert sur le message d'alerte.
3. **Top IP sources** — table sur l'adresse source.
4. **Répartition par priorité** — camembert sur la priorité Snort.

Enregistrer sous « Détection d'intrusions ».

## 4. Lecture pour le rapport

Pour chaque capture, expliquer en 2-3 lignes : la signature déclenchée, le
scénario correspondant, l'IP source et la cible, la menace représentée, et la
réaction attendue de l'administrateur.
