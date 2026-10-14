"""
Secure AI Gateway - Etape 4 : journalisation (audit).

Principe FONDAMENTAL : on n'enregistre JAMAIS de donnee en clair.
Uniquement des metadonnees, qui permettent l'audit (qui a fait quoi, quand,
avec quelle decision) tout en respectant la minimisation (art. 5 RGPD).

Pour prouver l'integrite du journal sans stocker le contenu, on garde une
empreinte cryptographique (SHA-256) de l'invite masquee : elle ne permet pas
de retrouver le texte, mais permet de verifier qu'un enregistrement n'a pas
ete modifie.

Base : audit.db (SQLite), creee automatiquement a cote des fichiers du projet.
"""

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_DB = Path(__file__).parent / "audit.db"


def _connexion():
    return sqlite3.connect(_DB)


def initialiser():
    """Cree la table d'audit si elle n'existe pas encore."""
    with _connexion() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS journal (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                horodatage        TEXT    NOT NULL,
                agent             TEXT    NOT NULL,
                role              TEXT    NOT NULL,
                cas_usage         TEXT    NOT NULL,
                decision          TEXT    NOT NULL,   -- AUTORISE / REFUSE
                motif             TEXT,                -- raison d'un refus
                entites_masquees  INTEGER NOT NULL,    -- combien d'identites protegees
                empreinte_invite  TEXT    NOT NULL,    -- SHA-256 de l'invite MASQUEE
                latence_ms        INTEGER              -- cout des controles
            )
        """)


def _empreinte(texte: str) -> str:
    """SHA-256 : preuve d'integrite, sans stocker le texte lui-meme."""
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()


def enregistrer(agent, role, cas_usage, decision,
                entites_masquees, invite_masquee,
                motif=None, latence_ms=0):
    """Ecrit une ligne d'audit. Ne recoit jamais l'invite en clair."""
    with _connexion() as conn:
        conn.execute("""
            INSERT INTO journal
              (horodatage, agent, role, cas_usage, decision, motif,
               entites_masquees, empreinte_invite, latence_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            agent, role, cas_usage, decision, motif,
            entites_masquees, _empreinte(invite_masquee), latence_ms,
        ))


def lire_tout():
    """Retourne toutes les lignes du journal (pour le point d'audit)."""
    with _connexion() as conn:
        conn.row_factory = sqlite3.Row
        lignes = conn.execute(
            "SELECT * FROM journal ORDER BY id DESC"
        ).fetchall()
        return [dict(l) for l in lignes]


# --- Test rapide : python journalisation.py --------------------------------

if __name__ == "__main__":
    initialiser()
    enregistrer(
        agent="k.mabou", role="uc_courrier", cas_usage="UC1",
        decision="AUTORISE", entites_masquees=4,
        invite_masquee="Redige une convocation pour <PERSON_1> ...",
        latence_ms=120,
    )
    enregistrer(
        agent="k.mabou", role="uc_synthese", cas_usage="UC2",
        decision="REFUSE", motif="usage interdit : demande d'avis diagnostique",
        entites_masquees=0,
        invite_masquee="Quel traitement prescrire pour ...",
        latence_ms=15,
    )
    print("Deux lignes ecrites. Contenu du journal :\n")
    for ligne in lire_tout():
        print(ligne)