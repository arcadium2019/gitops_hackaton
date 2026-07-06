#!/usr/bin/env python3
"""
AI Remediator — Équipe 8
Boucle : VulnerabilityReports (Trivy) -> analyse IA (AI Endpoints OVHcloud)
         -> correctif YAML -> Pull Request GitHub -> revue humaine -> merge
         -> Argo CD resync -> cluster corrigé.

Env requis :
  OVH_AI_ENDPOINTS_ACCESS_TOKEN  clé AI Endpoints
  GITHUB_TOKEN                   token GitHub (repo scope)
  GITHUB_REPO                    ex: equipe8/gitops-repo
  KUBECONFIG                     (optionnel, sinon in-cluster)

Usage :
  python remediator.py            # un cycle
  python remediator.py --watch    # boucle continue (60s)
"""

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

# --- Config -----------------------------------------------------------------
AI_URL = os.environ.get(
    "OVH_AI_BASE_URL",
    "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions",
)
AI_MODEL = os.environ.get("OVH_AI_MODEL", "Meta-Llama-3_3-70B-Instruct")
AI_TOKEN = os.environ["OVH_AI_ENDPOINTS_ACCESS_TOKEN"]
GH_TOKEN = os.environ["GITHUB_TOKEN"]
GH_REPO = os.environ["GITHUB_REPO"]  # "owner/name"
WORKLOADS_DIR = "workloads/vulnerable"
SEVERITIES = {"CRITICAL", "HIGH"}


def kubectl_json(*args):
    out = subprocess.check_output(["kubectl", *args, "-o", "json"])
    return json.loads(out)


# --- 1. Détection : lire les rapports Trivy ---------------------------------
def get_vulnerabilities():
    """Retourne [{workload, namespace, container, image, cves:[...]}]"""
    reports = kubectl_json("get", "vulnerabilityreports", "-A")
    findings = []
    for r in reports.get("items", []):
        labels = r["metadata"].get("labels", {})
        if labels.get("trivy-operator.resource.namespace") != "demo":
            continue
        vulns = [
            {
                "id": v["vulnerabilityID"],
                "severity": v["severity"],
                "title": v.get("title", ""),
                "installed": v.get("installedVersion", ""),
                "fixed": v.get("fixedVersion", ""),
            }
            for v in r["report"].get("vulnerabilities", [])
            if v["severity"] in SEVERITIES
        ][:15]  # limite pour le prompt
        if vulns:
            findings.append(
                {
                    "workload": labels.get("trivy-operator.resource.name", "?"),
                    "kind": labels.get("trivy-operator.resource.kind", "?"),
                    "namespace": labels.get("trivy-operator.resource.namespace", "?"),
                    "container": labels.get("trivy-operator.container.name", "?"),
                    "image": r["report"]["artifact"].get("repository", "")
                    + ":"
                    + r["report"]["artifact"].get("tag", ""),
                    "cves": vulns,
                }
            )
    return findings


# --- 2. Analyse + correctif par IA -------------------------------------------
PROMPT = """Tu es un expert sécurité Kubernetes. Voici un manifeste YAML déployé \
et les vulnérabilités détectées par Trivy Operator.

MANIFESTE ACTUEL :
```yaml
{manifest}
```

VULNÉRABILITÉS ({workload}) :
{vulns}

Corrige le manifeste : mets à jour chaque image vers une version PATCHÉE et \
ÉPINGLÉE (jamais :latest — ex nginx 1.27.x, redis 7.4.x), supprime privileged, \
ajoute un securityContext non-root (runAsNonRoot: true, runAsUser >= 1000, \
allowPrivilegeEscalation: false, capabilities drop ALL), ajoute des resources \
requests/limits raisonnables. ATTENTION : l'image nginx standard ne peut pas \
tourner en non-root — remplace-la par nginxinc/nginx-unprivileged (port 8080, \
adapte containerPort). Ne change RIEN d'autre (noms, labels, namespaces, \
replicas identiques).

Réponds en deux blocs EXACTEMENT :
EXPLICATION: <3 phrases max sur les failles et les corrections>
```yaml
<le manifeste complet corrigé>
```"""


def call_ai(manifest, finding):
    vulns_txt = "\n".join(
        f"- {c['id']} ({c['severity']}) {c['title']} — installé {c['installed']}, corrigé en {c['fixed']}"
        for c in finding["cves"]
    )
    body = json.dumps(
        {
            "model": AI_MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": PROMPT.format(
                        manifest=manifest,
                        workload=finding["workload"],
                        vulns=vulns_txt,
                    ),
                }
            ],
            "temperature": 0.1,
            "max_tokens": 2500,
        }
    ).encode()
    req = urllib.request.Request(
        AI_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {AI_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        content = json.load(resp)["choices"][0]["message"]["content"]
    explanation = ""
    m = re.search(r"EXPLICATION:\s*(.*?)```", content, re.S)
    if m:
        explanation = m.group(1).strip()
    y = re.search(r"```yaml\s*(.*?)```", content, re.S)
    if not y:
        raise ValueError("Pas de YAML dans la réponse IA:\n" + content[:500])
    return explanation, y.group(1).strip() + "\n"


# --- 3. Pull Request GitHub ---------------------------------------------------
def gh(method, path, payload=None):
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        data=json.dumps(payload).encode() if payload else None,
        method=method,
        headers={
            "Authorization": f"Bearer {GH_TOKEN}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub {method} {path}: {e.code} {e.read().decode()[:300]}")


def open_pr(file_path, new_content, explanation, finding):
    branch = f"ai-fix/{finding['workload']}-{int(time.time())}"
    main = gh("GET", f"/repos/{GH_REPO}/git/ref/heads/main")
    gh(
        "POST",
        f"/repos/{GH_REPO}/git/refs",
        {"ref": f"refs/heads/{branch}", "sha": main["object"]["sha"]},
    )
    current = gh("GET", f"/repos/{GH_REPO}/contents/{file_path}?ref={branch}")
    gh(
        "PUT",
        f"/repos/{GH_REPO}/contents/{file_path}",
        {
            "message": f"fix(security): remédiation IA pour {finding['workload']}",
            "content": base64.b64encode(new_content.encode()).decode(),
            "sha": current["sha"],
            "branch": branch,
        },
    )
    cves = ", ".join(c["id"] for c in finding["cves"][:8])
    pr = gh(
        "POST",
        f"/repos/{GH_REPO}/pulls",
        {
            "title": f"🤖 [AI] Correctif sécurité — {finding['workload']}",
            "head": branch,
            "base": "main",
            "body": f"""## Remédiation automatique (AI Endpoints OVHcloud)

**Workload :** `{finding['namespace']}/{finding['workload']}` (image `{finding['image']}`)
**CVEs ({len(finding['cves'])}) :** {cves}

### Analyse de l'IA
{explanation}

---
*PR générée automatiquement par la chaîne d'audit. Revue humaine requise avant merge.
Après merge, Argo CD resynchronise le cluster automatiquement.*""",
        },
    )
    return pr["html_url"]


# --- Boucle -------------------------------------------------------------------
def already_open_pr(workload):
    prs = gh("GET", f"/repos/{GH_REPO}/pulls?state=open")
    return any(workload in p["title"] for p in prs)


def run_once():
    findings = get_vulnerabilities()
    print(f"[audit] {len(findings)} workload(s) vulnérable(s) détecté(s)")
    if not findings:
        return
    # Tous les workloads demo sont dans le même fichier -> UNE seule PR
    # regroupant toutes les vulnérabilités (évite les PR en conflit).
    merged = {
        "workload": "demo-workloads",
        "kind": "Deployment",
        "namespace": "demo",
        "container": ", ".join(f["container"] for f in findings),
        "image": ", ".join(f["image"] for f in findings),
        "cves": [c for f in findings for c in f["cves"]],
    }
    if already_open_pr(merged["workload"]):
        print("  - PR déjà ouverte pour demo-workloads, skip")
        return
    print(f"  - {len(merged['cves'])} CVE HIGH/CRITICAL au total → analyse IA...")
    path = f"{WORKLOADS_DIR}/vulnerable-app.yaml"
    manifest = base64.b64decode(
        gh("GET", f"/repos/{GH_REPO}/contents/{path}")["content"]
    ).decode()
    explanation, fixed = call_ai(manifest, merged)
    url = open_pr(path, fixed, explanation, merged)
    print(f"    ✅ PR ouverte : {url}")


if __name__ == "__main__":
    if "--watch" in sys.argv:
        while True:
            try:
                run_once()
            except Exception as e:
                print("ERREUR:", e)
            time.sleep(60)
    else:
        run_once()
