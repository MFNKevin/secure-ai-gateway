// Secure AI Gateway - Etape 9 : portail utilisateur (III.3.2).
// Vanilla JS, sans etape de build : conforme a "Application web legere
// (HTML/React)" (tableau III.4), sans la complexite d'outillage React
// pour un prototype sans budget.

const KEYCLOAK_URL = "http://localhost:8080";
const REALM = "secure-ai-gateway";
const CLIENT_ID = "gateway-client";

const ROLE_PAR_CAS_USAGE = { UC1: "uc_courrier", UC2: "uc_synthese", UC3: "uc_procedures" };

// Contenu pedagogique par cas d'usage : sert a la fois d'explication a
// l'ecran et de source pour les exemples cliquables de la demonstration.
const INFOS_CAS_USAGE = {
  UC1: {
    titre: "UC1 - Redaction de courrier administratif",
    role: "uc_courrier",
    description:
      "Un agent administratif redige un courrier (convocation, attestation...). " +
      "Toute identite citee est masquee avant l'envoi au modele, puis reinjectee " +
      "uniquement dans la reponse qui vous est destinee.",
    exemples: [
      {
        etiquette: "Cas autorise",
        texte: "Redige une convocation pour Mme DUPONT Claire, nee le 12/03/1958, IPP 0004589, consultation de cardiologie le 15/09 a 10h.",
        refus: false,
      },
      {
        etiquette: "Cas refuse - usage personnel",
        texte: "Peux-tu me donner une recette de cuisine pour ce soir ?",
        refus: true,
      },
    ],
  },
  UC2: {
    titre: "UC2 - Synthese de compte rendu medical",
    role: "uc_synthese",
    description:
      "Reserve au personnel soignant. Masquage renforce : si plus de 15 identites " +
      "sont detectees dans une seule demande, elle est bloquee par prudence. Toute " +
      "demande d'avis diagnostique ou therapeutique est egalement refusee.",
    exemples: [
      {
        etiquette: "Cas autorise",
        texte: "Resume ce compte rendu : Patient MARTIN Paul, ne le 10/05/1970, NIR 1 70 05 75 123 456 78, IPP 1234567. Consultation de suivi en cardiologie, examen sans particularite, poursuite du traitement en cours.",
        refus: false,
      },
      {
        etiquette: "Cas refuse - avis diagnostique",
        texte: "Le patient MARTIN Paul presente une fievre a 39 degres. Quel diagnostic et quel traitement proposer ?",
        refus: true,
      },
    ],
  },
  UC3: {
    titre: "UC3 - Assistant de procedures internes",
    role: "uc_procedures",
    description:
      "Repond uniquement a partir des procedures internes dont VOTRE role autorise " +
      "la consultation. Un document reserve a un autre profil (ex. administrateur) " +
      "n'est jamais recupere, meme si la question le vise directement.",
    exemples: [
      {
        etiquette: "Cas autorise",
        texte: "Quelle est la procedure d'admission en ambulatoire ?",
        refus: false,
      },
      {
        etiquette: "Filtre par role - document hors droits",
        texte: "Comment gerer les comptes Keycloak et les habilitations des agents ?",
        refus: true,
      },
    ],
  },
};

let etat = { token: null, agent: null, roles: [] };

// --- Utilitaires -------------------------------------------------------

function decoderJeton(jeton) {
  const charge = jeton.split(".")[1];
  return JSON.parse(atob(charge.replace(/-/g, "+").replace(/_/g, "/")));
}

function afficher(id, visible) {
  document.getElementById(id).hidden = !visible;
}

// --- Connexion (grant direct aupres de Keycloak) -----------------------
// Simplification assumee du prototype : le client "gateway-client" est
// configure en "direct access grants" (sans redirection SSO complete),
// faute d'annuaire Active Directory reel a federer (cf. limite documentee
// au chapitre III : "federe avec l'annuaire existant" reste une cible).

async function seConnecter(utilisateur, motDePasse) {
  const reponse = await fetch(`${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      client_id: CLIENT_ID,
      username: utilisateur,
      password: motDePasse,
    }),
  });
  if (!reponse.ok) throw new Error("Identifiants incorrects");

  const donnees = await reponse.json();
  const charge = decoderJeton(donnees.access_token);

  etat.token = donnees.access_token;
  etat.agent = charge.preferred_username;
  etat.roles = charge.realm_access?.roles || [];
}

function seDeconnecter() {
  etat = { token: null, agent: null, roles: [] };
  afficher("ecran-connexion", true);
  afficher("ecran-principal", false);
}

// --- Appels a la passerelle ---------------------------------------------

async function envoyerChat(invite, casUsage) {
  const reponse = await fetch("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${etat.token}` },
    body: JSON.stringify({ invite, cas_usage: casUsage }),
  });
  const donnees = await reponse.json();
  if (!reponse.ok) throw new Error(donnees.detail || "Erreur inconnue");
  return donnees;
}

async function chargerAudit() {
  const reponse = await fetch("/audit", {
    headers: { "Authorization": `Bearer ${etat.token}` },
  });
  if (!reponse.ok) throw new Error("Acces refuse au journal d'audit");
  return reponse.json();
}

// --- Jeu de donnees fictives (III.7.3) : recherche d'un patient existant ---
// Le pipeline de securite en aval est identique, que l'invite vienne d'une
// fiche existante ou d'une saisie libre : ceci ne fait que remplir le champ.

async function rechercherPatients(recherche) {
  const reponse = await fetch(`/patients?recherche=${encodeURIComponent(recherche)}`, {
    headers: { "Authorization": `Bearer ${etat.token}` },
  });
  if (!reponse.ok) return [];
  return reponse.json();
}

async function obtenirPatient(id) {
  const reponse = await fetch(`/patients/${id}`, {
    headers: { "Authorization": `Bearer ${etat.token}` },
  });
  if (!reponse.ok) throw new Error("Patient introuvable");
  return reponse.json();
}

// --- Mise a jour de l'interface apres connexion -------------------------

function apresConnexion() {
  afficher("ecran-connexion", false);
  afficher("ecran-principal", true);

  document.getElementById("zone-identite").innerHTML =
    `${etat.agent} (${etat.roles.join(", ") || "aucun role"}) <button id="bouton-deconnexion">Se deconnecter</button>`;
  document.getElementById("bouton-deconnexion").addEventListener("click", seDeconnecter);

  // N'affiche que les cas d'usage couverts par un role de l'agent.
  const select = document.getElementById("champ-cas-usage");
  for (const option of select.options) {
    option.disabled = !etat.roles.includes(ROLE_PAR_CAS_USAGE[option.value]);
  }
  const premiereAutorisee = [...select.options].find((o) => !o.disabled);
  if (premiereAutorisee) select.value = premiereAutorisee.value;
  majZoneCasUsage();

  afficher("onglet-audit", etat.roles.includes("auditeur"));
}

// --- Onglets --------------------------------------------------------------

function activerOnglet(nom) {
  for (const bouton of document.querySelectorAll(".onglet")) {
    bouton.classList.toggle("actif", bouton.dataset.onglet === nom);
  }
  afficher("vue-assistant", nom === "assistant");
  afficher("vue-audit", nom === "audit");
  if (nom === "audit") rafraichirAudit();
}

async function rafraichirAudit() {
  const corps = document.getElementById("corps-table-audit");
  corps.innerHTML = "<tr><td colspan='7'>Chargement...</td></tr>";
  try {
    const lignes = await chargerAudit();
    corps.innerHTML = lignes.map((l) => `
      <tr>
        <td>${l.horodatage}</td><td>${l.agent}</td><td>${l.cas_usage}</td>
        <td>${l.decision}</td><td>${l.motif ?? ""}</td>
        <td>${l.entites_masquees}</td><td>${l.latence_ms ?? ""}</td>
      </tr>`).join("");
  } catch (e) {
    corps.innerHTML = `<tr><td colspan="7" class="erreur">${e.message}</td></tr>`;
  }
}

// --- Cablage des evenements -----------------------------------------------

document.getElementById("formulaire-connexion").addEventListener("submit", async (evt) => {
  evt.preventDefault();
  const erreur = document.getElementById("erreur-connexion");
  erreur.textContent = "";
  try {
    await seConnecter(
      document.getElementById("champ-utilisateur").value,
      document.getElementById("champ-mdp").value,
    );
    apresConnexion();
    activerOnglet("assistant");
  } catch (e) {
    erreur.textContent = e.message;
  }
});

document.getElementById("formulaire-chat").addEventListener("submit", async (evt) => {
  evt.preventDefault();
  const invite = document.getElementById("champ-invite").value.trim();
  const casUsage = document.getElementById("champ-cas-usage").value;
  const erreur = document.getElementById("erreur-chat");
  erreur.textContent = "";
  afficher("zone-reponse", false);
  if (!invite) return;

  afficher("indicateur-attente", true);
  try {
    const donnees = await envoyerChat(invite, casUsage);
    document.getElementById("texte-reponse").textContent = donnees.reponse;
    document.getElementById("detail-invite-masquee").textContent = donnees.invite_masquee;
    document.getElementById("detail-entites").textContent = donnees.entites_masquees;
    document.getElementById("detail-latence-passerelle").textContent = donnees.latence_passerelle_ms;
    document.getElementById("detail-latence-modele").textContent = donnees.latence_modele_ms;

    const etapesNormales = donnees.etapes.filter((e) => !e.startsWith("[ALERTE]"));
    const alertes = donnees.etapes.filter((e) => e.startsWith("[ALERTE]"));

    document.getElementById("liste-etapes").innerHTML =
      etapesNormales.map((e) => `<li>${e.replace(/^\d+\.\s*/, "")}</li>`).join("");

    const zoneAlerte = document.getElementById("zone-alerte-residuelle");
    if (alertes.length) {
      zoneAlerte.textContent = alertes.map((a) => a.replace("[ALERTE] ", "")).join(" ");
      afficher("zone-alerte-residuelle", true);
    } else {
      afficher("zone-alerte-residuelle", false);
    }

    const parType = Object.entries(donnees.entites_par_type || {})
      .map(([type, n]) => `${n} ${type}`).join(", ");
    document.getElementById("detail-entites-par-type").textContent = parType || "aucune";

    const zoneSources = document.getElementById("zone-sources");
    if (donnees.sources && donnees.sources.length) {
      document.getElementById("liste-sources").innerHTML =
        donnees.sources.map((s) => `<li>${s}</li>`).join("");
      afficher("zone-sources", true);
    } else {
      afficher("zone-sources", false);
    }

    afficher("zone-reponse", true);
  } catch (e) {
    erreur.textContent = e.message;
  } finally {
    afficher("indicateur-attente", false);
  }
});

for (const bouton of document.querySelectorAll(".onglet")) {
  bouton.addEventListener("click", () => activerOnglet(bouton.dataset.onglet));
}
document.getElementById("bouton-rafraichir-audit").addEventListener("click", rafraichirAudit);

// --- Explication et exemples par cas d'usage (clarte pour la demonstration) --

function majZoneCasUsage() {
  const casUsage = document.getElementById("champ-cas-usage").value;
  const infos = INFOS_CAS_USAGE[casUsage];

  afficher("zone-patient", casUsage === "UC1" || casUsage === "UC2");

  document.getElementById("zone-explication-uc").innerHTML = `
    <span class="badge-role">role requis : ${infos.role}</span>
    <h3>${infos.titre}</h3>
    <p>${infos.description}</p>
  `;

  document.getElementById("boutons-exemples").innerHTML = infos.exemples.map((ex, i) => `
    <button type="button" class="bouton-exemple ${ex.refus ? "attendu-refus" : ""}" data-index="${i}">
      <span class="etiquette">${ex.etiquette}</span>${ex.texte}
    </button>
  `).join("");

  for (const bouton of document.querySelectorAll(".bouton-exemple")) {
    bouton.addEventListener("click", () => {
      document.getElementById("champ-invite").value = infos.exemples[bouton.dataset.index].texte;
    });
  }
}

document.getElementById("champ-cas-usage").addEventListener("change", majZoneCasUsage);

let delaiRecherche = null;
document.getElementById("champ-recherche-patient").addEventListener("input", (evt) => {
  clearTimeout(delaiRecherche);
  const terme = evt.target.value.trim();
  const liste = document.getElementById("liste-resultats-patients");
  if (!terme) { liste.innerHTML = ""; return; }
  delaiRecherche = setTimeout(async () => {
    const patients = await rechercherPatients(terme);
    liste.innerHTML = patients.map((p) =>
      `<li data-id="${p.id}">${p.prenom} ${p.nom} - ne(e) le ${p.date_naissance}</li>`
    ).join("") || "<li>Aucun resultat</li>";
  }, 250);
});

document.getElementById("liste-resultats-patients").addEventListener("click", async (evt) => {
  const id = evt.target.dataset.id;
  if (!id) return;

  const casUsage = document.getElementById("champ-cas-usage").value;
  const patient = await obtenirPatient(id);
  const champInvite = document.getElementById("champ-invite");

  if (casUsage === "UC1") {
    champInvite.value =
      `Redige une convocation pour ${patient.prenom} ${patient.nom}, ` +
      `ne(e) le ${patient.date_naissance}, NIR ${patient.nir}, ${patient.ipp}, ` +
      `pour une consultation de suivi.`;
  } else if (casUsage === "UC2" && patient.comptes_rendus.length) {
    champInvite.value = `Resume ce compte rendu :\n\n${patient.comptes_rendus[0].contenu}`;
  } else if (casUsage === "UC2") {
    champInvite.value = `(Aucun compte rendu enregistre pour ${patient.prenom} ${patient.nom})`;
  }

  document.getElementById("liste-resultats-patients").innerHTML = "";
  document.getElementById("champ-recherche-patient").value = "";
});

majZoneCasUsage();
