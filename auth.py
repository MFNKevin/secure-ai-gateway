"""
Secure AI Gateway - Etape 5 : authentification et autorisation.

Verifie les jetons emis par Keycloak (OpenID Connect) et en extrait
l'identite de l'agent et ses roles applicatifs. La passerelle ne fait
jamais confiance a une identite declarative fournie par le client :
tout repose sur la signature du jeton, verifiee ici.
"""

import os

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# KEYCLOAK_URL : adresse utilisee par la passerelle pour JOINDRE Keycloak
# (peut etre interne au reseau Docker, ex. http://keycloak:8080).
# KEYCLOAK_ISSUER_URL : adresse telle qu'elle apparait dans le champ "iss"
# des jetons - toujours celle exposee cote hote/navigateur, meme depuis un
# conteneur, puisque c'est par la que les jetons sont obtenus. Les deux
# peuvent diverger en environnement conteneurise ; a defaut, on suppose
# qu'elles sont identiques (cas de l'execution native).
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_ISSUER_URL = os.environ.get("KEYCLOAK_ISSUER_URL", KEYCLOAK_URL)
REALM = "secure-ai-gateway"
ISSUER = f"{KEYCLOAK_ISSUER_URL}/realms/{REALM}"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"

# Cases d'usage metier -> role Keycloak habilite a les invoquer (tableau III.1).
ROLE_PAR_CAS_USAGE = {
    "UC1": "uc_courrier",
    "UC2": "uc_synthese",
    "UC3": "uc_procedures",
}

_jwks_client = jwt.PyJWKClient(JWKS_URL)

# Declare un vrai schema de securite HTTP Bearer : Swagger affiche alors un
# bouton "Authorize" qui memorise le jeton pour tous les essais, plutot
# qu'un simple champ de formulaire par requete (peu fiable au copier-coller).
_bearer_scheme = HTTPBearer(auto_error=False, description="Jeton Keycloak (access_token)")


def verifier_jeton(identifiants: HTTPAuthorizationCredentials = Depends(_bearer_scheme)) -> dict:
    """Dependance FastAPI : verifie le jeton Bearer, retourne agent + roles.

    Leve une 401 si le jeton est absent, invalide, expire ou mal signe.
    """
    if identifiants is None:
        raise HTTPException(status_code=401, detail="Jeton d'authentification manquant")

    jeton = identifiants.credentials
    try:
        cle_signature = _jwks_client.get_signing_key_from_jwt(jeton).key
        contenu = jwt.decode(
            jeton, cle_signature, algorithms=["RS256"],
            issuer=ISSUER, options={"verify_aud": False},
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Jeton invalide : {e}")

    return {
        "agent": contenu.get("preferred_username", contenu.get("sub")),
        "roles": contenu.get("realm_access", {}).get("roles", []),
    }


def exiger_role(roles_autorises: list[str]):
    """Fabrique une dependance qui exige l'un des roles donnes (ex. 'auditeur')."""

    def _verifier(identite: dict = Depends(verifier_jeton)) -> dict:
        if not any(r in identite["roles"] for r in roles_autorises):
            raise HTTPException(status_code=403, detail="Role insuffisant pour cette ressource")
        return identite

    return _verifier
