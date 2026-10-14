"""
Secure AI Gateway - Etape 8 : indexation hors ligne du corpus de procedures
(III.4.3 : "le flux d'indexation documentaire du cas UC3 s'execute hors
ligne, entre la documentation interne et la base vectorielle").

A relancer a chaque modification du corpus (procedures/corpus.py) :
  python indexation.py
"""

import asyncio

import chromadb

from procedures.corpus import PROCEDURES
from rag import CHROMA_HOST, CHROMA_PORT, COLLECTION, embedding


async def indexer():
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    collection = client.get_or_create_collection(COLLECTION)

    ids, documents, metadonnees, embeddings = [], [], [], []
    for procedure in PROCEDURES:
        vecteur = await embedding(procedure["contenu"])
        ids.append(procedure["id"])
        documents.append(procedure["contenu"])
        metadonnees.append({
            "titre": procedure["titre"],
            "roles_autorises": procedure["roles_autorises"],
        })
        embeddings.append(vecteur)
        print(f"  indexe : {procedure['id']} - {procedure['titre']}")

    collection.upsert(ids=ids, documents=documents, metadatas=metadonnees, embeddings=embeddings)
    print(f"\n{len(ids)} procedures indexees dans la collection '{COLLECTION}'.")


if __name__ == "__main__":
    asyncio.run(indexer())
