# Secure AI Gateway

Prototype de passerelle sécurisée entre les agents d'un établissement public de santé et un modèle d'IA générative **local** (Ollama / Mistral). Aucune identité de patient n'atteint le modèle : chaque demande est authentifiée, anonymisée, contrôlée par des politiques, puis journalisée sans donnée en clair.

```
Jeton Keycloak → contrôle de rôle → ANONYMISATION (Presidio + spaCy)
   → POLITIQUES (Open Policy Agent) → modèle local (Ollama)
   → RÉ-IDENTIFICATION côté passerelle → réponse
   └─> JOURNALISATION (métadonnées + empreinte SHA-256 uniquement)
```

## Cas d'usage

| Cas | Rôle Keycloak | Description |
|-----|---------------|-------------|
| UC1 | `uc_courrier` | Rédaction de courriers administratifs |
| UC2 | `uc_synthese` | Synthèse de comptes rendus médicaux |
| UC3 | `uc_procedures` | Assistant sur les procédures internes (RAG, ChromaDB, filtrage par rôle à la recherche) |
| — | `auditeur` | Lecture seule du journal d'audit (`/audit`) |

## Stack

FastAPI · Presidio / spaCy (`fr_core_news_md`) · Keycloak (OIDC) · Open Policy Agent · Ollama (`mistral`, `nomic-embed-text`) · ChromaDB · SQLite · Caddy (TLS) · Loki + Grafana (supervision) · Docker Compose

## Structure

```
main.py               Point d'entrée FastAPI (/chat, /audit, /patients)
auth.py               Vérification des jetons Keycloak (JWKS, RS256)
anonymisation.py      Masquage / ré-identification des entités
politiques.py         Détection de signaux + décision OPA (fail-closed)
journalisation.py     Journal d'audit SQLite (métadonnées uniquement)
rag.py, indexation.py UC3 : recherche vectorielle filtrée par rôle
donnees_fictives.py   Génération du jeu de patients fictifs (Faker)
scenarios_test.py     Scénarios nominaux et adversariaux
procedures/           Corpus de procédures internes fictives
frontend/             Portail agent (HTML/JS, sans build)
opa/policies/         Règles d'usage (Rego)
keycloak/import/      Realm de démonstration (rôles + comptes de test)
grafana/provisioning/ Datasource Loki + tableau de bord
```

## Démarrage

Prérequis : Docker Desktop, le plugin Docker Loki (`docker plugin install grafana/loki-docker-driver:latest --alias loki --grant-all-permissions`).

```bash
# 1. Créer le fichier du journal d'audit (sinon Docker créerait un dossier à la place)
#    Windows PowerShell : New-Item audit.db -ItemType File
touch audit.db

# 2. Lancer la pile
docker compose up -d --build

# 3. Télécharger les modèles dans Ollama (première fois)
docker compose exec ollama ollama pull mistral
docker compose exec ollama ollama pull nomic-embed-text

# 4. Indexer le corpus de procédures (UC3) depuis l'hôte
python -m venv .venv && .venv/Scripts/activate   # Linux/macOS : source .venv/bin/activate
pip install -r requirements.txt
python indexation.py
```

- Portail : https://localhost:8443 (certificat auto-signé) ou http://localhost:8000
- Swagger : http://localhost:8000/docs
- Grafana : http://localhost:3000

> Le volume Ollama utilise `${USERPROFILE}/.ollama` (Windows). Sous Linux/macOS, remplacer par `${HOME}/.ollama`.

Régénérer les patients fictifs : `python donnees_fictives.py`

## Tests

```bash
python scenarios_test.py                 # tous les scénarios
python scenarios_test.py --sans-nominaux # uniquement les adversariaux (rapide)
```

## ⚠️ Avertissement

Projet **de démonstration / académique**, non destiné à la production :

- Les comptes Keycloak (`Passw0rd!`) et le mot de passe admin Keycloak (`admin_dev_password`) sont des identifiants de **démonstration** publics. Ne jamais les réutiliser.
- Keycloak tourne en `start-dev` avec `sslRequired: none` ; Grafana autorise l'accès anonyme.
- Toutes les données patients sont **fictives** (Faker) ; les NIR/IPP respectent le format mais ne sont pas réels.
- La détection des usages interdits repose sur des mots-clés : c'est une première ligne de défense, pas une garantie.
