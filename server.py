import os
import re
import json
import requests
import jwt

from datetime import datetime
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

load_dotenv()

mcp = FastMCP("MCP Server SOC")

# CONFIGURATION KEYCLOAK
KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER", "http://localhost:8080/realms/SOC")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "mcp-soc")
KEYCLOAK_JWKS_URL = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"

# RBAC
ROLES_AUTORISES = {
    "L1": ["lecture"],
    "L2": ["lecture", "investigation", "incident"],
    "L3": ["lecture", "investigation", "incident", "response"],
    "RSSI": ["lecture", "investigation", "incident", "response", "administration"]
}


def verifier_role(role: str, permission: str) -> bool:
    return permission in ROLES_AUTORISES.get(role.upper(), [])

# SANITISATION ANTI-INJECTION
MOTS_CLES_INJECTION = [
    "tu es maintenant", "your new role", "forget previous",
    "do not follow", "jailbreak", "dan mode", "prompt:",
    "instruction:", "ignore previous", "ignore all",
    "disregard", "override",
]

TAILLE_MAX_SORTIE = 8000


def sanitiser_sortie(texte: str) -> str:
    """Nettoie une sortie d'outil avant envoi au LLM."""
    if not texte:
        return ""

    if len(texte) > TAILLE_MAX_SORTIE:
        texte = texte[:TAILLE_MAX_SORTIE] + "\n[...tronqué]"

    for mot in MOTS_CLES_INJECTION:
        if mot.lower() in texte.lower():
            texte = re.sub(
                re.escape(mot),
                f"[MOT-SUSPECT:{mot}]",
                texte,
                flags=re.IGNORECASE
            )

    texte = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", texte)

    return texte

# LISTE BLANCHE ACTIFS PROTÉGÉS
WHITELIST_PATH = os.path.join(os.path.dirname(__file__), "whitelist.json")


def charger_whitelist() -> dict:
    """Charge la liste blanche depuis whitelist.json."""
    try:
        with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("actifs_proteges", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {"ips_critiques": [], "agents_critiques": []}


def est_ip_protegee(ip: str) -> bool:
    """Vérifie si une IP est dans la liste blanche."""
    wl = charger_whitelist()
    return ip.strip() in wl.get("ips_critiques", [])


def est_agent_protege(agent_id: str) -> bool:
    """Vérifie si un agent est dans la liste blanche."""
    wl = charger_whitelist()
    return agent_id.strip() in wl.get("agents_critiques", [])

# JOURNAL D'AUDIT
AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit.log")


def ecrire_audit(outil: str, args: dict, role: str, resultat: str) -> None:
    """Écrit une ligne dans le journal d'audit."""
    try:
        timestamp = datetime.utcnow().isoformat() + "Z"
        ligne = (
            f"{timestamp} | outil={outil} | role={role} | "
            f"args={args} | resultat={resultat[:80]}\n"
        )
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(ligne)
    except Exception:
        pass

# AUTHENTIFICATION JWT KEYCLOAK
def obtenir_role_jwt() -> str:
    # MODE TEST
    if os.getenv("MCP_TEST_MODE") == "1":
        return "L3"

    headers = get_http_headers(include={"authorization"})
    autorisation = headers.get("authorization", "")

    if not autorisation:
        raise ValueError("Authentification requise.")

    if not autorisation.startswith("Bearer "):
        raise ValueError("Format Authorization invalide.")

    token = autorisation[7:].strip()
    if not token:
        raise ValueError("Token JWT absent.")

    try:
        reponse = requests.get(KEYCLOAK_JWKS_URL, timeout=10)
        reponse.raise_for_status()
        cles = reponse.json().get("keys", [])

        header_jwt = jwt.get_unverified_header(token)
        kid = header_jwt.get("kid")
        if not kid:
            raise ValueError("Identifiant de clé JWT absent.")

        cle_jwk = next((cle for cle in cles if cle.get("kid") == kid), None)
        if cle_jwk is None:
            raise ValueError("Clé de signature JWT introuvable.")

        cle_publique = jwt.algorithms.RSAAlgorithm.from_jwk(cle_jwk)

        donnees = jwt.decode(
            token, cle_publique, algorithms=["RS256"],
            issuer=KEYCLOAK_ISSUER, options={"verify_aud": False}
        )

        if donnees.get("azp") != KEYCLOAK_CLIENT_ID:
            raise ValueError("Client Keycloak non autorisé.")

        roles = donnees.get("realm_access", {}).get("roles", [])
        roles_soc = [r.upper() for r in roles if r.upper() in ROLES_AUTORISES]

        if not roles_soc:
            raise ValueError("Aucun rôle SOC valide trouvé dans le JWT.")

        return roles_soc[0]

    except jwt.ExpiredSignatureError:
        raise ValueError("Le JWT a expiré.")
    except jwt.InvalidTokenError:
        raise ValueError("JWT invalide.")
    except requests.RequestException:
        raise ValueError("Impossible de contacter Keycloak.")

# OUTIL DE VÉRIFICATION
@mcp.tool()
def hello() -> str:
    """Vérifie que le serveur MCP fonctionne."""
    return "MCP SOC opérationnel"

# SIEM
@mcp.tool()
def query_siem(agent_id: str = "", limit: int = 10) -> str:
    """Recherche des événements SIEM dans Wazuh Indexer."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "investigation"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission investigation."

    mdp = os.getenv("WAZUH_INDEXER_PASSWORD")
    if not mdp:
        return "Mot de passe Wazuh Indexer absent."
    if limit < 1 or limit > 100:
        return "La limite doit être comprise entre 1 et 100."

    requete = {"size": limit, "sort": [{"@timestamp": {"order": "desc"}}]}
    if agent_id:
        requete["query"] = {"term": {"agent.id": agent_id}}

    reponse = requests.post(
        "https://192.168.20.10:9200/wazuh-alerts-4.x-*/_search",
        auth=("admin", mdp), json=requete, verify=False
    )
    reponse.raise_for_status()
    alertes = reponse.json().get("hits", {}).get("hits", [])

    if not alertes:
        return "Aucun événement trouvé."

    resultat = []
    for a in alertes:
        s = a.get("_source", {})
        resultat.append(
            f"Date : {s.get('@timestamp', 'Inconnue')}\n"
            f"Agent : {s.get('agent', {}).get('name', 'Inconnu')}\n"
            f"Niveau : {s.get('rule', {}).get('level', 'Inconnu')}\n"
            f"Règle : {s.get('rule', {}).get('description', 'Inconnue')}\n"
            f"Message : {s.get('full_log', 'Inconnu')}\n"
            f"{'-' * 50}"
        )
    return sanitiser_sortie("\n".join(resultat))


@mcp.tool()
def get_alerts(limit: int = 10) -> str:
    """Récupère les dernières alertes Wazuh."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "lecture"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission lecture."

    mdp = os.getenv("WAZUH_INDEXER_PASSWORD")
    if not mdp:
        return "Mot de passe Wazuh Indexer absent."
    if limit < 1 or limit > 100:
        return "La limite doit être comprise entre 1 et 100."

    reponse = requests.get(
        f"https://192.168.20.10:9200/wazuh-alerts-4.x-*/_search?size={limit}&sort=@timestamp:desc",
        auth=("admin", mdp), verify=False
    )
    reponse.raise_for_status()
    alertes = reponse.json().get("hits", {}).get("hits", [])

    if not alertes:
        return "Aucune alerte trouvée."

    resultat = []
    for a in alertes:
        s = a.get("_source", {})
        resultat.append(
            f"Date : {s.get('@timestamp', 'Inconnue')}\n"
            f"Agent : {s.get('agent', {}).get('name', 'Inconnu')}\n"
            f"Niveau : {s.get('rule', {}).get('level', 'Inconnu')}\n"
            f"Règle : {s.get('rule', {}).get('description', 'Inconnue')}\n"
            f"Message : {s.get('full_log', 'Inconnu')}\n"
            f"{'-' * 50}"
        )
    return sanitiser_sortie("\n".join(resultat))


@mcp.tool()
def search_ioc(ioc: str) -> str:
    """Recherche un IOC dans les alertes Wazuh."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "investigation"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission investigation."

    mdp = os.getenv("WAZUH_INDEXER_PASSWORD")
    if not mdp:
        return "Mot de passe Wazuh Indexer absent."
    if not ioc.strip():
        return "IOC vide."

    requete = {
        "size": 20,
        "query": {"query_string": {"query": f'"{ioc}"'}},
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    reponse = requests.post(
        "https://192.168.20.10:9200/wazuh-alerts-4.x-*/_search",
        auth=("admin", mdp), json=requete, verify=False
    )
    reponse.raise_for_status()
    alertes = reponse.json().get("hits", {}).get("hits", [])

    if not alertes:
        return f"Aucune alerte trouvée pour l'IOC : {ioc}"

    resultat = [f"IOC recherché : {ioc}", f"Nombre de résultats : {len(alertes)}", ""]
    for a in alertes:
        s = a.get("_source", {})
        resultat.append(
            f"Date : {s.get('@timestamp', 'Inconnue')}\n"
            f"Agent : {s.get('agent', {}).get('name', 'Inconnu')}\n"
            f"Niveau : {s.get('rule', {}).get('level', 'Inconnu')}\n"
            f"Règle : {s.get('rule', {}).get('description', 'Inconnue')}\n"
            f"Message : {s.get('full_log', 'Inconnu')}\n"
            f"{'-' * 50}"
        )
    return sanitiser_sortie("\n".join(resultat))


@mcp.tool()
def get_timeline(agent_id: str = "", limit: int = 20) -> str:
    """Chronologie des événements d'un agent."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "investigation"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission investigation."

    mdp = os.getenv("WAZUH_INDEXER_PASSWORD")
    if not mdp:
        return "Mot de passe Wazuh Indexer absent."
    if limit < 1 or limit > 100:
        return "La limite doit être comprise entre 1 et 100."

    requete = {"size": limit, "sort": [{"@timestamp": {"order": "asc"}}]}
    if agent_id:
        requete["query"] = {"term": {"agent.id": agent_id}}

    reponse = requests.post(
        "https://192.168.20.10:9200/wazuh-alerts-4.x-*/_search",
        auth=("admin", mdp), json=requete, verify=False
    )
    reponse.raise_for_status()
    alertes = reponse.json().get("hits", {}).get("hits", [])

    if not alertes:
        return "Aucun événement trouvé."

    resultat = []
    for a in alertes:
        s = a.get("_source", {})
        resultat.append(
            f"Date : {s.get('@timestamp', 'Inconnue')}\n"
            f"Agent : {s.get('agent', {}).get('name', 'Inconnu')}\n"
            f"Niveau : {s.get('rule', {}).get('level', 'Inconnu')}\n"
            f"Règle : {s.get('rule', {}).get('description', 'Inconnue')}\n"
            f"Message : {s.get('full_log', 'Inconnu')}\n"
            f"{'-' * 50}"
        )
    return sanitiser_sortie("\n".join(resultat))

# THREAT INTELLIGENCE
@mcp.tool()
def lookup_ip(ip: str) -> str:
    """Enrichit une IP avec AbuseIPDB."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "investigation"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission investigation."

    cle = os.getenv("ABUSEIPDB_API_KEY")
    if not cle:
        return "Clé API AbuseIPDB absente."
    if not ip.strip():
        return "Adresse IP vide."

    reponse = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": cle, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10
    )
    reponse.raise_for_status()
    d = reponse.json().get("data", {})

    resultat = (
        f"IP : {d.get('ipAddress', 'Inconnue')}\n"
        f"Pays : {d.get('countryCode', 'Inconnu')}\n"
        f"Score d'abus : {d.get('abuseConfidenceScore', 'Inconnu')}\n"
        f"Nombre de rapports : {d.get('totalReports', 'Inconnu')}\n"
        f"Dernier rapport : {d.get('lastReportedAt', 'Inconnu')}\n"
        f"Usage : {d.get('usageType', 'Inconnu')}"
    )
    return sanitiser_sortie(resultat)


@mcp.tool()
def analyze_hash(hash_fichier: str) -> str:
    """Analyse un hash avec VirusTotal."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "investigation"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission investigation."

    cle = os.getenv("VIRUSTOTAL_API_KEY")
    if not cle:
        return "Clé API VirusTotal absente."
    if not hash_fichier.strip():
        return "Hash vide."

    reponse = requests.get(
        f"https://www.virustotal.com/api/v3/files/{hash_fichier}",
        headers={"x-apikey": cle}, timeout=10
    )

    if reponse.status_code == 404:
        return f"Aucun fichier trouvé pour le hash : {hash_fichier}"

    reponse.raise_for_status()
    attrs = reponse.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    resultat = (
        f"Hash : {hash_fichier}\n"
        f"Type : {attrs.get('type_description', 'Inconnu')}\n"
        f"Nom : {attrs.get('meaningful_name', 'Inconnu')}\n"
        f"Malveillant : {stats.get('malicious', 0)}\n"
        f"Sous surveillance : {stats.get('suspicious', 0)}\n"
        f"Non détecté : {stats.get('undetected', 0)}"
    )
    return sanitiser_sortie(resultat)


@mcp.tool()
def get_cve_info(cve_id: str) -> str:
    """Récupère les infos d'une CVE depuis la NVD."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "investigation"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission investigation."

    if not cve_id.strip():
        return "Identifiant CVE vide."

    reponse = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id}, timeout=10
    )

    if reponse.status_code == 404:
        return f"CVE introuvable : {cve_id}"

    reponse.raise_for_status()
    vulns = reponse.json().get("vulnerabilities", [])
    if not vulns:
        return f"Aucune information trouvée pour : {cve_id}"

    cve = vulns[0].get("cve", {})
    descs = cve.get("descriptions", [])
    desc = "Inconnue"
    for d in descs:
        if d.get("lang") == "en":
            desc = d.get("value", "Inconnue")
            break

    resultat = (
        f"CVE : {cve_id}\n"
        f"Statut : {cve.get('vulnStatus', 'Inconnu')}\n"
        f"Description : {desc}"
    )
    return sanitiser_sortie(resultat)

# RESPONSE
@mcp.tool()
def block_ip_firewall(ip: str) -> str:
    """Bloque une IP (DRY-RUN)."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        ecrire_audit("block_ip_firewall", {"ip": ip}, "anonymous", f"REFUS:{e}")
        return f"Accès refusé : {e}"

    if not verifier_role(role, "response"):
        ecrire_audit("block_ip_firewall", {"ip": ip}, role, "REFUS:permission")
        return f"Accès refusé : le rôle {role} ne possède pas la permission response."

    if not ip.strip():
        return "Adresse IP vide."

    if est_ip_protegee(ip):
        ecrire_audit("block_ip_firewall", {"ip": ip}, role, "BLOQUE:whitelist")
        return (
            f"ACTION BLOQUEE : l'IP {ip} est un actif protege "
            "(liste blanche).\n"
            "Aucune action n'a ete effectuee.\n"
            "Validation humaine requise pour toute exception."
        )

    ecrire_audit("block_ip_firewall", {"ip": ip}, role, "DRY-RUN autorise")
    return (
        f"DRY-RUN : blocage demandé pour l'adresse IP {ip}.\n"
        "Aucune modification réelle du pare-feu n'a été effectuée."
    )


@mcp.tool()
def isolate_endpoint(agent_id: str) -> str:
    """Isole un endpoint (DRY-RUN)."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        ecrire_audit("isolate_endpoint", {"agent_id": agent_id}, "anonymous", f"REFUS:{e}")
        return f"Accès refusé : {e}"

    if not verifier_role(role, "response"):
        ecrire_audit("isolate_endpoint", {"agent_id": agent_id}, role, "REFUS:permission")
        return f"Accès refusé : le rôle {role} ne possède pas la permission response."

    if not agent_id.strip():
        return "Identifiant de l'agent vide."

    if est_agent_protege(agent_id):
        ecrire_audit("isolate_endpoint", {"agent_id": agent_id}, role, "BLOQUE:whitelist")
        return (
            f"ACTION BLOQUEE : l'agent {agent_id} est un actif protege "
            "(liste blanche).\n"
            "Aucune isolation n'a ete effectuee.\n"
            "Validation humaine requise pour toute exception."
        )

    ecrire_audit("isolate_endpoint", {"agent_id": agent_id}, role, "DRY-RUN autorise")
    return (
        f"DRY-RUN : demande d'isolement de l'agent {agent_id}.\n"
        "Aucune isolation réelle n'a été effectuée."
    )


@mcp.tool()
def create_incident(titre: str, description: str) -> str:
    """Crée un incident (DRY-RUN)."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "incident"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission incident."

    if not titre.strip():
        return "Titre de l'incident vide."
    if not description.strip():
        return "Description de l'incident vide."

    return (
        "DRY-RUN : création d'un incident.\n"
        f"Titre : {titre}\n"
        f"Description : {description}\n"
        "Aucun incident réel n'a été créé."
    )


@mcp.tool()
def send_notification(message: str) -> str:
    """Envoie une notification (DRY-RUN)."""
    try:
        role = obtenir_role_jwt()
    except ValueError as e:
        return f"Accès refusé : {e}"

    if not verifier_role(role, "incident"):
        return f"Accès refusé : le rôle {role} ne possède pas la permission incident."

    if not message.strip():
        return "Message vide."

    return (
        "DRY-RUN : notification demandée.\n"
        f"Message : {message}\n"
        "Aucune notification réelle n'a été envoyée."
    )

# DEMARRAGE DU SERVEUR MCP
if __name__ == "__main__":
    mcp.run(
        transport="sse",
        host="0.0.0.0",
        port=8000
    )
