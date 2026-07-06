# Rapport d'architecture — Chaîne d'audit & remédiation GitOps

**Équipe 8 — Hackathon OVHcloud x Ynov, 6-7 juillet 2026**

## 1. Vue d'ensemble

Notre chaîne implémente la boucle demandée : une faille détectée sur le cluster est analysée par une IA générative qui propose un correctif sous forme de Pull Request ; après revue humaine et merge, Argo CD resynchronise automatiquement le cluster. L'IA n'est pas un assistant externe mais un composant actif de la chaîne de sécurité.

```
┌─────────────────────── Cluster Managed Kubernetes OVHcloud ───────────────────────┐
│                                                                                    │
│  workloads demo ──scan──> Trivy Operator ──VulnerabilityReports (CRD)──┐          │
│       ▲                   Falco (runtime) ── alertes ──────────────────┤          │
│       │                   Kyverno (policies) ── PolicyReports ─────────┤          │
│       │ sync                                                           │          │
│   Argo CD <── merge ── revue humaine <── Pull Request <── AI Remediator│          │
│       │                                        ▲                       │          │
└───────┼────────────────────────────────────────┼───────────────────────┼──────────┘
        │                                        │                       │
   dépôt Git (GitHub) <────────────────── AI Endpoints OVHcloud <────────┘
                                          (analyse + correctif YAML)
```

## 2. Rôle de chaque composant

**Argo CD** (GitOps) : le dépôt Git est l'unique source de vérité. Un pattern *app-of-apps* (`bootstrap/root-app.yaml`) déploie les applications `vulnerable-workloads` et `kyverno-policies` avec sync automatique, prune et self-heal.

**Trivy Operator** (audit) : scanne en continu les images des workloads et publie des CRD `VulnerabilityReport` par ReplicaSet, avec sévérités CVSS.

**Falco** (runtime) : détecte les comportements suspects en cours d'exécution (shell dans un conteneur, lecture de fichiers sensibles), complémentaire à l'analyse statique de Trivy.

**Kyverno** (policy-as-code) : trois ClusterPolicies en mode Audit — interdiction des conteneurs privilégiés, limits obligatoires, interdiction de root. Le mode Audit permet de laisser les workloads vulnérables tourner pour la démo tout en produisant des PolicyReports.

**Prometheus** (observabilité) : kube-prometheus-stack expose les métriques du cluster et des composants de la chaîne.

**AI Remediator** (couche IA, code maison) : service Python qui (1) lit les `VulnerabilityReports` HIGH/CRITICAL du namespace demo, (2) récupère le manifeste concerné depuis Git, (3) demande à AI Endpoints OVHcloud (Llama 3.3 70B) un manifeste corrigé — image patchée, securityContext durci, limits — avec explication, (4) ouvre une Pull Request sur le dépôt. La revue humaine reste obligatoire : l'IA propose, l'humain valide, Argo CD applique.

## 3. Choix d'architecture

La remédiation passe par Git et non par un patch direct du cluster : cela préserve le principe GitOps (aucune modification hors Git), garde une trace auditable de chaque correctif et impose un contrôle humain avant application. Le remediator est idempotent (pas de PR en double par workload) et sans dépendance externe (stdlib Python). Trivy a été préféré à Kubescape pour ses CRD natives faciles à consommer par la couche IA.

## 4. Statut CNCF des composants

| Outil | Rôle | Statut CNCF |
|---|---|---|
| Argo CD | GitOps — sync Git → cluster | Graduated |
| Trivy Operator | Audit de sécurité (CVE) | CNCF validé (Aqua Security) |
| Falco | Détection de menaces runtime | Graduated |
| Kyverno | Policy-as-code | Graduated |
| Prometheus | Observabilité & métriques | Graduated |
| AI Endpoints | IA générative (Llama 3.3 70B) | OVHcloud |
