"""
Secure AI Gateway - Etape 8 : corpus de procedures internes fictives (III.7.3).

Chaque document porte une etiquette "roles_autorises" : "tous" signifie
visible par tout detenteur du role uc_procedures ; un role precis
(uc_courrier, uc_synthese, admin, auditeur) restreint le document aux
agents qui detiennent EN PLUS ce role-la. C'est ce filtrage, applique au
moment de la recherche vectorielle, qui empeche l'exfiltration indirecte
decrite en III.3.3 : un agent ne doit pas pouvoir faire ressortir, par une
question habile, un document reserve a un autre profil.
"""

PROCEDURES = [
    {
        "id": "proc-01",
        "titre": "Procedure d'admission en ambulatoire",
        "roles_autorises": "tous",
        "contenu": (
            "L'admission en ambulatoire se fait au guichet des admissions le jour meme "
            "de l'intervention, sur presentation d'une piece d'identite et de la lettre "
            "de convocation. Le patient doit se presenter a jeun si l'intervention le "
            "requiert, et etre accompagne pour son retour. La sortie est prononcee par "
            "le medecin apres surveillance post-operatoire d'au moins deux heures."
        ),
    },
    {
        "id": "proc-02",
        "titre": "Charte d'usage de l'assistant d'IA generative",
        "roles_autorises": "tous",
        "contenu": (
            "L'assistant d'IA generative de l'etablissement ne doit etre utilise que "
            "pour la redaction de courriers administratifs, la synthese de comptes "
            "rendus et la consultation des procedures internes. Toute demande d'avis "
            "diagnostique, de prescription, ou toute utilisation a des fins "
            "personnelles est strictement interdite et journalisee. Chaque reponse "
            "generee doit etre relue et validee par l'agent avant tout usage."
        ),
    },
    {
        "id": "proc-03",
        "titre": "Procedure d'acces au dossier patient informatise (DPI)",
        "roles_autorises": "uc_synthese",
        "contenu": (
            "L'acces au dossier patient informatise est reserve au personnel soignant "
            "habilite. Toute consultation est journalisee avec l'identite du soignant, "
            "l'horodatage et le motif d'acces. L'acces a un dossier hors de son service "
            "d'affectation doit etre justifie et peut faire l'objet d'un controle "
            "a posteriori par le DPO."
        ),
    },
    {
        "id": "proc-04",
        "titre": "Procedure de courrier de sortie d'hospitalisation",
        "roles_autorises": "uc_synthese",
        "contenu": (
            "Le courrier de sortie est redige par le medecin ou avec son assistance, "
            "puis transmis au medecin traitant sous 48 heures. Il doit mentionner le "
            "diagnostic principal, les traitements prescrits et les consignes de "
            "suivi. Toute synthese assistee par IA doit porter la mention "
            "'genere par IA' et etre signee par le soignant."
        ),
    },
    {
        "id": "proc-05",
        "titre": "Procedure de traitement du courrier administratif entrant",
        "roles_autorises": "uc_courrier",
        "contenu": (
            "Le courrier entrant est receptionne, tamponne et scanne le jour meme, "
            "puis oriente vers le service concerne sous 24 heures. Les convocations "
            "et attestations sont produites a partir des modeles valides par la "
            "direction. Toute demande urgente est signalee au responsable de service."
        ),
    },
    {
        "id": "proc-06",
        "titre": "Protocole de gestion d'un incident de securite informatique",
        "roles_autorises": "admin",
        "contenu": (
            "Tout incident de securite suspecte doit etre signale immediatement a la "
            "direction des systemes d'information, qui isole le systeme concerne et "
            "ouvre une investigation. Le RSSI evalue la necessite d'une notification "
            "a la CNIL sous 72 heures conformement a l'article 33 du RGPD. Le journal "
            "d'audit de la passerelle constitue une source de preuve prioritaire."
        ),
    },
    {
        "id": "proc-07",
        "titre": "Procedure d'habilitation et de gestion des comptes Keycloak",
        "roles_autorises": "admin",
        "contenu": (
            "La creation d'un compte agent dans Keycloak suit le principe du moindre "
            "privilege : un seul role applicatif est attribue par defaut, correspondant "
            "au cas d'usage metier de l'agent. Toute demande de role supplementaire "
            "doit etre validee par le responsable hierarchique et tracee. Les comptes "
            "inactifs depuis plus de six mois sont desactives automatiquement."
        ),
    },
    {
        "id": "proc-08",
        "titre": "Procedure d'audit periodique du journal de la passerelle",
        "roles_autorises": "auditeur",
        "contenu": (
            "Le DPO et le RSSI consultent mensuellement le journal d'audit de la "
            "passerelle afin de verifier l'absence d'anomalies : refus repetes, "
            "tentatives d'acces hors role, latences excessives. Un rapport de synthese "
            "est transmis a la direction chaque trimestre. Le journal est conserve "
            "douze mois conformement au tableau de retention des donnees."
        ),
    },
]
