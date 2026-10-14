"""
Secure AI Gateway - Etape 12 : jeu de donnees fictives (III.7.3).

Aucune donnee reelle : une cinquantaine de patients et une trentaine de
comptes rendus entierement generes par Faker (locale fr_FR), stockes dans
une base SQLite dediee (donnees.db), separee de audit.db. Les NIR/IPP
respectent le FORMAT attendu par anonymisation.py mais ne sont pas des
identifiants reels ni valides au sens de l'INSEE.

Regeneration :  python donnees_fictives.py
"""

import random
import sqlite3
from pathlib import Path

from faker import Faker

_DB = Path(__file__).parent / "donnees.db"

N_PATIENTS = 50
N_COMPTES_RENDUS = 30

SERVICES = [
    "cardiologie", "pneumologie", "chirurgie orthopedique",
    "geriatrie", "pediatrie", "neurologie",
]

_MODELES_COMPTE_RENDU = [
    "Compte rendu de consultation - {service}.\n"
    "Patient : {prenom} {nom}, ne(e) le {date_naissance}, NIR {nir}, {ipp}.\n"
    "Le {date_acte}, consultation de suivi en {service}. L'examen clinique "
    "est sans particularite notable. Le patient rapporte une amelioration "
    "progressive depuis la derniere visite. Poursuite du traitement en cours, "
    "prochain rendez-vous de controle a prevoir dans trois mois.",

    "Compte rendu d'hospitalisation - {service}.\n"
    "Patient : {prenom} {nom}, ne(e) le {date_naissance}, NIR {nir}, {ipp}.\n"
    "Admission le {date_acte} pour surveillance en {service}. Le sejour s'est "
    "deroule sans complication. Les examens complementaires realises durant "
    "l'hospitalisation sont revenus dans les limites de la normale. Sortie "
    "autorisee avec consignes de suivi habituelles.",

    "Compte rendu operatoire - {service}.\n"
    "Patient : {prenom} {nom}, ne(e) le {date_naissance}, NIR {nir}, {ipp}.\n"
    "Intervention realisee le {date_acte} en {service}, sans incident "
    "peroperatoire. Les suites immediates sont simples. Le patient est "
    "transfere en salle de reveil puis en service conventionnel pour la "
    "poursuite de la surveillance post-operatoire.",
]


def _nir_fictif(faker: Faker) -> str:
    """Format valide (15 chiffres, prefixe 1 ou 2) mais entierement fictif."""
    sexe = random.choice("12")
    aa = f"{random.randint(0, 99):02d}"
    mm = f"{random.randint(1, 12):02d}"
    dept = f"{random.randint(1, 95):02d}"
    commune = f"{random.randint(1, 999):03d}"
    ordre = f"{random.randint(1, 999):03d}"
    cle = f"{random.randint(0, 99):02d}"
    return f"{sexe} {aa} {mm} {dept} {commune} {ordre} {cle}"


def _ipp_fictif() -> str:
    return f"IPP {random.randint(1000, 9999999):07d}"


def generer():
    faker = Faker("fr_FR")

    with sqlite3.connect(_DB) as conn:
        conn.execute("DROP TABLE IF EXISTS comptes_rendus")
        conn.execute("DROP TABLE IF EXISTS patients")
        conn.execute("""
            CREATE TABLE patients (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                nom             TEXT NOT NULL,
                prenom          TEXT NOT NULL,
                date_naissance  TEXT NOT NULL,
                nir             TEXT NOT NULL,
                ipp             TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE comptes_rendus (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id  INTEGER NOT NULL REFERENCES patients(id),
                service     TEXT NOT NULL,
                date_acte   TEXT NOT NULL,
                contenu     TEXT NOT NULL
            )
        """)

        patients = []
        for _ in range(N_PATIENTS):
            nom = faker.last_name().upper()
            prenom = faker.first_name()
            naissance = faker.date_of_birth(minimum_age=1, maximum_age=95).strftime("%d/%m/%Y")
            nir = _nir_fictif(faker)
            ipp = _ipp_fictif()
            cur = conn.execute(
                "INSERT INTO patients (nom, prenom, date_naissance, nir, ipp) VALUES (?, ?, ?, ?, ?)",
                (nom, prenom, naissance, nir, ipp),
            )
            patients.append({
                "id": cur.lastrowid, "nom": nom, "prenom": prenom,
                "date_naissance": naissance, "nir": nir, "ipp": ipp,
            })

        for _ in range(N_COMPTES_RENDUS):
            patient = random.choice(patients)
            service = random.choice(SERVICES)
            date_acte = faker.date_between(start_date="-2y", end_date="today").strftime("%d/%m/%Y")
            contenu = random.choice(_MODELES_COMPTE_RENDU).format(
                service=service, date_acte=date_acte, **patient,
            )
            conn.execute(
                "INSERT INTO comptes_rendus (patient_id, service, date_acte, contenu) VALUES (?, ?, ?, ?)",
                (patient["id"], service, date_acte, contenu),
            )

    print(f"{N_PATIENTS} patients et {N_COMPTES_RENDUS} comptes rendus generes dans {_DB.name}.")


# --- Consultation (utilisee par la passerelle, jamais par le modele) -------

def rechercher_patients(recherche: str, limite: int = 10) -> list[dict]:
    """Recherche par nom ou prenom (sous-chaine, insensible a la casse)."""
    with sqlite3.connect(_DB) as conn:
        conn.row_factory = sqlite3.Row
        motif = f"%{recherche}%"
        lignes = conn.execute(
            "SELECT id, nom, prenom, date_naissance FROM patients "
            "WHERE nom LIKE ? OR prenom LIKE ? LIMIT ?",
            (motif, motif, limite),
        ).fetchall()
        return [dict(l) for l in lignes]


def obtenir_patient(patient_id: int) -> dict | None:
    """Fiche patient complete, avec ses comptes rendus (pour UC1/UC2)."""
    with sqlite3.connect(_DB) as conn:
        conn.row_factory = sqlite3.Row
        patient = conn.execute(
            "SELECT * FROM patients WHERE id = ?", (patient_id,),
        ).fetchone()
        if patient is None:
            return None
        comptes_rendus = conn.execute(
            "SELECT id, service, date_acte, contenu FROM comptes_rendus "
            "WHERE patient_id = ? ORDER BY id DESC",
            (patient_id,),
        ).fetchall()
        resultat = dict(patient)
        resultat["comptes_rendus"] = [dict(c) for c in comptes_rendus]
        return resultat


if __name__ == "__main__":
    generer()
