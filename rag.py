"""
Secure AI Gateway - Etape 8 : UC3, assistant de reponse aux procedures
internes (RAG - generation augmentee par la recherche).

Le point de securite decisif (III.3.3) : le filtrage par role est applique
AU MOMENT MEME de la recherche vectorielle (clause "where" de ChromaDB),
et non apres coup sur la reponse. Un extrait reserve a un autre profil
n'est donc jamais candidat a la generation : impossible pour un agent de
le faire ressortir par une question habile (exfiltration indirecte).

Indexation hors ligne :  python indexation.py
"""

import os

import chromadb
import httpx

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODELE_EMBEDDINGS = "nomic-embed-text"
CHROMA_HOST = os.environ.get("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8001"))
COLLECTION = "procedures"


def _client():
    return chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)


async def embedding(texte: str) -> list[float]:
    """Calcule l'embedding d'un texte via le modele local (Ollama)."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(
            f"{OLLAMA_URL}/api/embeddings",
            json={"model": MODELE_EMBEDDINGS, "prompt": texte},
        )
        r.raise_for_status()
        return r.json()["embedding"]


async def rechercher(question: str, roles_agent: list[str], k: int = 3) -> list[dict]:
    """Retourne les k extraits de procedures les plus pertinents, filtres
    par role AVANT la recherche : un role non autorise ne peut jamais
    faire remonter un document qui ne lui est pas destine.
    """
    autorises = list(set(roles_agent) | {"tous"})
    vecteur = await embedding(question)

    collection = _client().get_or_create_collection(COLLECTION)
    resultats = collection.query(
        query_embeddings=[vecteur],
        n_results=k,
        where={"roles_autorises": {"$in": autorises}},
    )

    extraits = []
    documents = resultats.get("documents", [[]])[0]
    metadonnees = resultats.get("metadatas", [[]])[0]
    for contenu, meta in zip(documents, metadonnees):
        extraits.append({"titre": meta.get("titre", "?"), "contenu": contenu})
    return extraits
