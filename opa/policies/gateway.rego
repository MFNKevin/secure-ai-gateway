# Secure AI Gateway - Etape 6 : politiques d'usage (Open Policy Agent).
#
# Traduit les usages interdits (III.3.3) en regle executable. La passerelle
# lui transmet des SIGNAUX deja detectes (booleens), jamais le contenu de
# l'invite : OPA ne fait pas d'analyse de texte, seulement de la decision.
#
# input attendu : {"signaux": {"avis_diagnostique": bool,
#                               "contournement_masquage": bool,
#                               "usage_personnel": bool}}

package gateway.politiques

import future.keywords.if
import future.keywords.in

default allow := true
default motif := ""

_motifs := {
	"avis_diagnostique": "usage interdit : demande d'avis diagnostique ou therapeutique",
	"contournement_masquage": "usage interdit : tentative de contournement du masquage des identites",
	"usage_personnel": "usage interdit : finalite etrangere au service (usage personnel)",
	"masquage_incertain": "refus par defaut : masquage juge incertain (trop d'entites detectees dans une seule invite)",
}

# Refus par defaut des que l'un des signaux d'usage interdit est present
# (fail-closed : en cas de doute, on bloque plutot que de laisser passer).
allow := false if {
	some cle
	input.signaux[cle] == true
}

motif := _motifs[cle] if {
	some cle
	input.signaux[cle] == true
}
