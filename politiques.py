"""
Secure AI Gateway - Etape 6 : moteur de politiques (usages interdits).

La passerelle ne fait jamais confiance a l'intention declaree par l'agent :
elle detecte elle-meme des SIGNAUX dans l'invite (mots-cles), puis delegue
la DECISION a Open Policy Agent, qui applique la regle (gateway.rego).
Cette separation correspond a III.6.2 : la detection reste ici, la
politique - modifiable sans toucher au code - vit dans le moteur.

Limite assumee : une detection par mots-cles est perfectible (comme le
module d'anonymisation sur le texte clinique francais, cf. III.8.2) ; elle
est une premiere ligne de defense, pas une garantie absolue.
"""

import os

import httpx

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181") + "/v1/data/gateway/politiques"

# --- Detection de signaux (mots-cles, sur l'invite deja masquee) -----------

_MOTS_AVIS_DIAGNOSTIQUE = (
    "diagnostic", "diagnostiquer", "prescri", "posologie", "ordonnance",
    "pathologie", "quel traitement", "quel medicament", "avis medical",
    "que dois-je prescrire", "recommandation therapeutique",
)

_MOTS_CONTOURNEMENT_MASQUAGE = (
    "ignore tes consignes", "ignore les consignes", "ignore tes instructions",
    "ignore les instructions", "oublie tes regles", "sans masquer",
    "donne-moi le nom reel", "remplace les jetons",
)

_MOTS_USAGE_PERSONNEL = (
    "recette de cuisine", "pour mon usage personnel", "en dehors du travail",
    "hors service", "devoir scolaire", "lettre de motivation personnelle",
)

# Au-dela de ce nombre d'entites masquees dans une seule invite, le masquage
# est juge incertain (trop dense pour etre pleinement fiable) et la demande
# est bloquee par prudence - cf. III.3.3 UC2 : "si le masquage echoue ou
# demeure incertain, la demande est bloquee plutot que transmise".
SEUIL_ENTITES_SATURATION = 15


def detecter_signaux(texte: str, nb_entites_masquees: int = 0) -> dict:
    """Cherche, par mots-cles, des indices des 4 familles d'usages interdits,
    plus un signal de saturation base sur la densite d'entites masquees.
    """
    t = texte.lower()
    return {
        "avis_diagnostique": any(m in t for m in _MOTS_AVIS_DIAGNOSTIQUE),
        "contournement_masquage": any(m in t for m in _MOTS_CONTOURNEMENT_MASQUAGE),
        "usage_personnel": any(m in t for m in _MOTS_USAGE_PERSONNEL),
        "masquage_incertain": nb_entites_masquees > SEUIL_ENTITES_SATURATION,
    }


# --- Decision (Open Policy Agent) -------------------------------------------

async def evaluer(texte_masque: str, nb_entites_masquees: int = 0) -> tuple[bool, str | None]:
    """Retourne (autorise, motif). motif est None si autorise."""
    signaux = detecter_signaux(texte_masque, nb_entites_masquees)
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.post(OPA_URL, json={"input": {"signaux": signaux}})
            r.raise_for_status()
            resultat = r.json()["result"]
        except (httpx.HTTPError, KeyError):
            # Refus par defaut (fail-closed) si le moteur de politiques est
            # injoignable : cf. III.3.2, l'indisponibilite d'un controle
            # ferme le service plutot que de le laisser passer sans controle.
            return False, "moteur de politiques injoignable"

    return resultat.get("allow", False), resultat.get("motif") or None
