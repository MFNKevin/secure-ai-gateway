"""
Secure AI Gateway - Etape 3 (v4) : module d'anonymisation.

Historique des versions (a documenter dans le chapitre IV) :
  v1 - detection de base : 3 vrais positifs, 2 faux positifs, 1 faux negatif.
  v2 - filtre des faux positifs + dates sans annee.
  v3 - tentative de detection des noms EN MAJUSCULES via Presidio : ECHEC.
       Presidio compile ses regex avec re.IGNORECASE : le motif "majuscules"
       masquait tous les mots de 3 lettres ou plus. De plus, les detections
       qui se chevauchaient corrompaient le texte masque.
  v4 - detection des majuscules realisee hors Presidio (casse maitrisee)
       et resolution des chevauchements (la meilleure detection l'emporte).
  v5 - fuite corrigee : sur "Mme BERNARD Sophie", spaCy ne capturait que
       "Mme BERNARD", laissant le prenom "Sophie" en clair dans le texte
       masque. Un mot capitalise adjacent a une entite PERSON est desormais
       rattache a celle-ci (ex. "MARTIN" + " Paul" -> une seule entite),
       sauf s'il chevauche une entite deja detectee separement.

La table de correspondance jeton -> valeur reelle NE SORT JAMAIS de la passerelle.
"""

import re

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

# --- Moteur d'analyse en francais ------------------------------------------

_configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "fr", "model_name": "fr_core_news_md"}],
}
_nlp_engine = NlpEngineProvider(nlp_configuration=_configuration).create_engine()
_analyseur = AnalyzerEngine(nlp_engine=_nlp_engine, supported_languages=["fr"])


# --- Detecteurs Presidio (contexte francais et hospitalier) ----------------

_nir = PatternRecognizer(
    supported_entity="NIR",
    supported_language="fr",
    patterns=[Pattern(
        name="nir",
        regex=r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b",
        score=0.9,
    )],
)

_ipp = PatternRecognizer(
    supported_entity="IPP",
    supported_language="fr",
    patterns=[Pattern(
        name="ipp",
        regex=r"\bIPP\s*:?\s*\d{4,10}\b",
        score=0.85,
    )],
)

_date_fr = PatternRecognizer(
    supported_entity="DATE_FR",
    supported_language="fr",
    patterns=[Pattern(
        name="date_fr",
        regex=r"\b\d{1,2}[/.-]\d{1,2}(?:[/.-]\d{2,4})?\b",
        score=0.8,
    )],
)

for _detecteur in (_nir, _ipp, _date_fr):
    _analyseur.registry.add_recognizer(_detecteur)

ENTITES = ["PERSON", "NIR", "IPP", "DATE_FR", "EMAIL_ADDRESS", "PHONE_NUMBER"]


# --- Detecteur de noms EN MAJUSCULES (hors Presidio) -----------------------
# Presidio applique re.IGNORECASE a ses motifs : impossible d'y exprimer
# "uniquement des majuscules". On le fait donc nous-memes, sans ce drapeau.
# Objectif : rattraper la convention hospitaliere "MARTIN Paul", que le
# modele spaCy, entraine sur du texte normal, ne reconnait pas.

_MOTIF_MAJUSCULES = re.compile(r"\b[A-ZÀ-ÖØ-Þ][A-ZÀ-ÖØ-Þ'\-]{2,}\b")
_SCORE_MAJUSCULES = 0.6   # modeste : spaCy, plus fiable, garde la priorite

# Mot capitalise (ex. prenom) immediatement colle a une entite PERSON,
# separe par un unique espace (pas de ponctuation entre les deux).
_MOT_CAPITALISE_ADJACENT = re.compile(r"^ ([A-ZÀ-Ö][a-zà-öø-ÿ'\-]+)\b")


# --- Filtre des faux positifs ----------------------------------------------

MOTS_IGNORES = {
    "redige", "rédige", "rediger", "rédiger", "ecris", "écris",
    "prepare", "prépare", "resume", "résume",
    "ne", "né", "nee", "née", "nes", "nés", "objet", "madame", "monsieur",
    "mme", "mlle", "mr", "m", "dr", "docteur", "professeur", "pr",
    "bonjour", "cordialement", "merci", "patient", "patiente", "service",
    "hopital", "hôpital", "consultation", "convocation", "courrier",
    "synthese", "synthèse", "compte", "rendu",
}

SIGLES_IGNORES = {
    "nir", "ipp", "chu", "chr", "ars", "samu", "smur", "ehpad",
    "orl", "irm", "tdm", "ecg", "urgences",
    "rgpd", "hds", "cnil", "anssi", "dinum", "dpi", "dpo", "rssi", "dsi",
    "ia", "llm", "api", "sso", "tls", "vpn", "pdf", "ok",
}


def _est_faux_positif(valeur: str, entite: str) -> bool:
    """Ecarte les detections PERSON manifestement erronees."""
    if entite != "PERSON":
        return False
    v = valeur.strip().lower().strip(".,;:!?")
    if v in MOTS_IGNORES or v in SIGLES_IGNORES:
        return True
    if len(v) < 3:
        return True
    return False


# --- Detection et resolution des chevauchements ----------------------------

def _detecter(texte: str):
    """Rassemble les detections Presidio + majuscules -> [(debut, fin, type, score)]."""
    trouvees = [
        (r.start, r.end, r.entity_type, r.score)
        for r in _analyseur.analyze(text=texte, language="fr", entities=ENTITES)
    ]
    trouvees += [
        (m.start(), m.end(), "PERSON", _SCORE_MAJUSCULES)
        for m in _MOTIF_MAJUSCULES.finditer(texte)
    ]
    return trouvees


def _rattacher_prenom_adjacent(texte, retenues):
    """Etend une entite PERSON au mot capitalise qui la suit immediatement.

    Rattrape le cas ou spaCy ne capture qu'une partie du nom (ex. "Mme
    BERNARD" pour "Mme BERNARD Sophie"), qui sinon laisserait le prenom
    en clair dans le texte masque.
    """
    etendues = []
    for debut, fin, entite, score in retenues:
        if entite == "PERSON":
            m = _MOT_CAPITALISE_ADJACENT.match(texte[fin:])
            if m:
                nouvelle_fin = fin + m.end()
                mot = m.group(1).lower()
                chevauche_autre = any(
                    nouvelle_fin > d and fin < f
                    for d, f, _, _ in retenues if (d, f) != (debut, fin)
                )
                if mot not in MOTS_IGNORES and not chevauche_autre:
                    fin = nouvelle_fin
        etendues.append((debut, fin, entite, score))
    return etendues


def _resoudre_chevauchements(trouvees):
    """Garde la meilleure detection quand deux se recouvrent.

    Sans cela, remplacer une entite contenue dans une autre (ex. "paul"
    a l'interieur de "paul.martin@example.fr") corrompt le texte masque.
    """
    # Meilleur score d'abord ; a score egal, la detection la plus longue.
    trouvees = sorted(trouvees, key=lambda d: (-d[3], -(d[1] - d[0])))

    retenues = []
    for d in trouvees:
        chevauche = any(d[0] < r[1] and r[0] < d[1] for r in retenues)
        if not chevauche:
            retenues.append(d)
    return retenues


# --- Fonctions publiques ---------------------------------------------------

def anonymiser(texte: str):
    """Remplace les identites par des jetons.

    Retourne (texte_masque, table) ou table = {"<PERSON_1>": "DUPONT Claire", ...}
    """
    trouvees = _detecter(texte)

    # 1. ecarter les faux positifs connus
    trouvees = [
        d for d in trouvees
        if not _est_faux_positif(texte[d[0]:d[1]], d[2])
    ]

    # 2. resoudre les chevauchements
    retenues = _resoudre_chevauchements(trouvees)

    # 2b. rattacher un prenom laisse hors de l'entite par spaCy
    retenues = _rattacher_prenom_adjacent(texte, retenues)

    # 3. remplacer en partant de la fin (sinon les positions se decalent)
    retenues.sort(key=lambda d: d[0], reverse=True)

    table = {}
    compteurs = {}
    texte_masque = texte

    for debut, fin, entite, _score in retenues:
        valeur = texte[debut:fin]

        jeton = next((j for j, v in table.items() if v == valeur), None)
        if jeton is None:
            compteurs[entite] = compteurs.get(entite, 0) + 1
            jeton = f"<{entite}_{compteurs[entite]}>"
            table[jeton] = valeur

        texte_masque = texte_masque[:debut] + jeton + texte_masque[fin:]

    return texte_masque, table


def reidentifier(texte: str, table: dict) -> str:
    """Reinjecte les valeurs reelles a la place des jetons."""
    for jeton, valeur in table.items():
        texte = texte.replace(jeton, valeur)
    return texte


# --- Test rapide : python anonymisation.py ---------------------------------

if __name__ == "__main__":
    exemples = [
        # UC1 nominal.
        "Rédige une convocation pour Mme DUPONT Claire, née le 12/03/1958, "
        "IPP 0004589, consultation de cardiologie le 15/09 à 10h.",

        # Nom en majuscules (convention hospitaliere) + NIR + coordonnees.
        "Le patient MARTIN Paul (NIR 1 58 03 75 116 001 45) doit être contacté "
        "au 06 12 34 56 78 ou à paul.martin@example.fr.",

        # Sigles a ne PAS masquer + nom en majuscules a masquer.
        "Compte rendu du CHU : Mme BERNARD Sophie a passé une IRM le 03/07.",
    ]

    for i, exemple in enumerate(exemples, 1):
        masque, table = anonymiser(exemple)
        print(f"--- Exemple {i} ---")
        print("AVANT :", exemple)
        print("APRES :", masque)
        print("TABLE :", table)
        print()