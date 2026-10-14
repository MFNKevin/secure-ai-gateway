"""
Secure AI Gateway - Etape 6 : authentification, anonymisation, politiques, journalisation.

Chaine complete :
  jeton Keycloak -> ROLE -> ANONYMISATION -> POLITIQUES (OPA) -> modele local -> REIDENTIFICATION -> reponse
                                                               \\-> JOURNALISATION (metadonnees, jamais de clair)

Prealable : Keycloak et OPA doivent tourner (docker compose up -d), et un
jeton doit etre obtenu aupres de Keycloak pour appeler /chat ou /audit.

Lancement :  uvicorn main:app --reload
Interface  :  http://127.0.0.1:8000/docs
"""

import os
import re
import time

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from anonymisation import anonymiser, reidentifier
from auth import ROLE_PAR_CAS_USAGE, exiger_role, verifier_jeton
import donnees_fictives
import journalisation
import politiques
import rag

# --- Configuration ---------------------------------------------------------

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434") + "/api/chat"
MODELE = "mistral"

CONSIGNE_SYSTEME = (
    "Tu es un assistant administratif d'un etablissement public de sante francais. "
    "Tu reponds TOUJOURS en francais, dans un style professionnel, clair et concis. "
    "Tu rediges uniquement des documents administratifs. "
    "Tu ne donnes jamais d'avis medical, de diagnostic ni de recommandation therapeutique. "
    "Le texte contient des jetons de la forme <PERSON_1> ou <DATE_FR_1> : "
    "recopie-les EXACTEMENT tels quels, sans jamais les traduire ni les remplacer."
)

# UC3 : consigne dediee au RAG (III.3.3) - repondre UNIQUEMENT a partir des
# extraits fournis, jamais d'invention, et citer le document source.
CONSIGNE_SYSTEME_UC3 = (
    "Tu es un assistant qui repond aux questions des agents sur les procedures "
    "internes de l'etablissement, exclusivement a partir des extraits de "
    "documents fournis ci-dessous. Cite le titre du document dont tu tires "
    "chaque information. Si les extraits ne permettent pas de repondre, dis-le "
    "clairement plutot que d'inventer une reponse."
)

app = FastAPI(title="Secure AI Gateway", version="0.6")


def _repartition_par_type(table: dict) -> dict:
    """Deduit le type de chaque entite masquee a partir du jeton (ex.
    '<PERSON_1>' -> 'PERSON'), pour l'expliciter dans l'interface sans
    jamais exposer la valeur reelle.
    """
    repartition = {}
    for jeton in table:
        m = re.match(r"^<(.+)_\d+>$", jeton)
        if m:
            repartition[m.group(1)] = repartition.get(m.group(1), 0) + 1
    return repartition


# La base d'audit est prete des le demarrage de la passerelle.
@app.on_event("startup")
def _demarrage():
    journalisation.initialiser()


# --- Modeles de donnees ----------------------------------------------------

class Demande(BaseModel):
    invite: str
    cas_usage: str = "UC1"


class Reponse(BaseModel):
    reponse: str
    invite_masquee: str
    entites_masquees: int
    entites_par_type: dict[str, int]
    latence_passerelle_ms: int
    latence_modele_ms: int
    sources: list[str] = []
    etapes: list[str]


# --- Points d'entree -------------------------------------------------------

@app.get("/sante")
def sante():
    return {"statut": "ok"}


# --- Jeu de donnees fictives (III.7.3) --------------------------------------
# Sert de "DPI simplifie" au portail : l'agent choisit un patient existant
# plutot que de retaper une identite de memoire. Le pipeline de securite en
# aval (anonymisation, politiques, modele, journalisation) est strictement
# identique, que l'invite vienne d'ici ou d'une saisie libre.

@app.get("/patients")
def rechercher_patients(recherche: str = "", identite: dict = Depends(exiger_role(["uc_courrier", "uc_synthese"]))):
    return donnees_fictives.rechercher_patients(recherche)


@app.get("/patients/{patient_id}")
def obtenir_patient(patient_id: int, identite: dict = Depends(exiger_role(["uc_courrier", "uc_synthese"]))):
    patient = donnees_fictives.obtenir_patient(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient introuvable")
    return patient


@app.post("/chat", response_model=Reponse)
async def chat(demande: Demande, identite: dict = Depends(verifier_jeton)):

    agent = identite["agent"]
    roles = identite["roles"]
    role_requis = ROLE_PAR_CAS_USAGE.get(demande.cas_usage)
    etapes = [f"1. Authentification : jeton Keycloak verifie, agent identifie comme '{agent}'."]

    # 1. CONTROLE : anonymisation de l'invite (avant toute journalisation,
    # afin de ne jamais faire l'empreinte d'un texte encore en clair).
    t0 = time.perf_counter()
    invite_masquee, table = anonymiser(demande.invite)
    t_anonymisation = time.perf_counter() - t0
    repartition = _repartition_par_type(table)
    if table:
        detail = ", ".join(f"{n} {t}" for t, n in repartition.items())
        etapes.append(f"2. Anonymisation : {len(table)} entite(s) masquee(s) avant tout envoi au modele ({detail}).")
    else:
        etapes.append("2. Anonymisation : aucune identite detectee dans le texte saisi.")

    # 2. CONTROLE : le role de l'agent couvre-t-il le cas d'usage demande ?
    if role_requis is None or role_requis not in roles:
        journalisation.enregistrer(
            agent=agent, role=",".join(roles) or "aucun", cas_usage=demande.cas_usage,
            decision="REFUSE", motif="role insuffisant pour ce cas d'usage",
            entites_masquees=len(table), invite_masquee=invite_masquee,
        )
        raise HTTPException(status_code=403, detail="Role insuffisant pour ce cas d'usage")
    etapes.append(f"3. Controle de role : '{role_requis}' couvre bien {demande.cas_usage}.")

    # 3. CONTROLE : moteur de politiques (usages interdits, III.3.3)
    autorise, motif = await politiques.evaluer(invite_masquee, len(table))
    if not autorise:
        journalisation.enregistrer(
            agent=agent, role=role_requis, cas_usage=demande.cas_usage,
            decision="REFUSE", motif=motif,
            entites_masquees=len(table), invite_masquee=invite_masquee,
        )
        raise HTTPException(status_code=403, detail=motif)
    etapes.append("4. Moteur de politiques (OPA) : aucun usage interdit detecte, demande autorisee.")

    # 4. Appel du modele local (il ne recoit que l'invite masquee)
    sources = []
    if demande.cas_usage == "UC3":
        # UC3 (RAG) : le filtrage par role a lieu DANS la recherche elle-meme
        # (rag.rechercher), pas apres coup - cf. III.3.3.
        extraits = await rag.rechercher(invite_masquee, roles)
        sources = [e["titre"] for e in extraits]
        contexte = "\n\n".join(f"[{e['titre']}]\n{e['contenu']}" for e in extraits)
        consigne = CONSIGNE_SYSTEME_UC3
        contenu_utilisateur = (
            f"Extraits de documents internes disponibles :\n\n{contexte}\n\n"
            f"Question de l'agent : {invite_masquee}"
        )
        if sources:
            etapes.append(f"5. Recherche documentaire (RAG) : {len(sources)} extrait(s) filtre(s) par role recupere(s).")
        else:
            etapes.append("5. Recherche documentaire (RAG) : aucun document autorise pour ce role ne correspond a la question.")
    else:
        consigne = CONSIGNE_SYSTEME
        contenu_utilisateur = invite_masquee

    charge_utile = {
        "model": MODELE,
        "messages": [
            {"role": "system", "content": consigne},
            {"role": "user", "content": contenu_utilisateur},
        ],
        "stream": False,
        # Garde le modele charge en memoire 30 min entre deux requetes,
        # pour eviter de repayer le cout de demarrage a froid (~6 min
        # constate) a chaque nouvelle demonstration.
        "keep_alive": "30m",
    }

    t1 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            r = await client.post(OLLAMA_URL, json=charge_utile)
            r.raise_for_status()
            donnees = r.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"Modele injoignable : {e}")
    t_modele = time.perf_counter() - t1
    etapes.append(f"6. Modele local (Ollama/{MODELE}) : execution hors ligne, n'a jamais recu que le texte masque.")

    reponse_brute = donnees["message"]["content"]

    # 5. CONTROLE : re-identification locale
    t2 = time.perf_counter()
    reponse_finale = reidentifier(reponse_brute, table)
    t_reidentification = time.perf_counter() - t2
    if table:
        etapes.append("7. Re-identification : les valeurs reelles sont reinjectees uniquement ici, cote passerelle, dans la reponse qui vous est destinee.")

    # Alerte : un espace reserve du type <XXX> encore present dans la reponse
    # finale ne peut pas venir de notre table d'anonymisation (nos jetons
    # suivent toujours le format <TYPE_numero>) - c'est une invention du
    # modele (cf. R6, hallucination), a signaler explicitement.
    jetons_residuels = sorted(set(re.findall(r"<[^<>]+>", reponse_finale)))
    if jetons_residuels:
        etapes.append(
            "[ALERTE] La reponse contient un ou plusieurs espaces reserves non "
            f"resolus ({', '.join(jetons_residuels)}) : le modele les a inventes, "
            "ils ne proviennent pas du systeme d'anonymisation. A verifier avant tout usage."
        )

    latence_passerelle_ms = int((t_anonymisation + t_reidentification) * 1000)

    # 6. CONTROLE : journalisation (metadonnees uniquement)
    journalisation.enregistrer(
        agent=agent,
        role=role_requis,
        cas_usage=demande.cas_usage,
        decision="AUTORISE",
        entites_masquees=len(table),
        invite_masquee=invite_masquee,
        latence_ms=latence_passerelle_ms,
    )
    etapes.append("8. Journalisation (SQLite) : seules des metadonnees sont ecrites (agent, role, decision, nombre d'entites, empreinte SHA-256 du texte masque) - jamais le nom, la date ou le texte genere.")

    # La table est abandonnee ici : rien de clair n'est conserve.
    return Reponse(
        reponse=reponse_finale,
        invite_masquee=invite_masquee,
        entites_masquees=len(table),
        entites_par_type=repartition,
        latence_passerelle_ms=latence_passerelle_ms,
        latence_modele_ms=int(t_modele * 1000),
        sources=sources,
        etapes=etapes,
    )


@app.get("/audit")
def audit(identite: dict = Depends(exiger_role(["auditeur"]))):
    """Consultation du journal, reservee au role auditeur (DPO / RSSI)."""
    return journalisation.lire_tout()


# --- Portail utilisateur (III.3.2) ------------------------------------------
# Monte APRES les routes API ci-dessus, qui restent prioritaires sur les
# memes chemins ; tout le reste (/, /app.js, /style.css) sert le frontend.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")