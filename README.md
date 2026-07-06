# Chaîne d'audit & remédiation GitOps — Équipe 8

Hackathon OVHcloud x Ynov — 6-7 juillet 2026

## Boucle cible

Détection (Trivy/Falco) → analyse + correctif IA (AI Endpoints OVHcloud) → PR automatique → revue humaine → merge → resync Argo CD → cluster corrigé.

## Structure

- `bootstrap/` — Application racine Argo CD (app-of-apps)
- `apps/` — Définitions des Applications Argo CD
- `workloads/vulnerable/` — Workloads volontairement vulnérables (démo)
- `policies/` — Policies Kyverno (policy-as-code)
- `ai-remediator/` — Couche IA : audit → correctif → Pull Request

## Stack (statut CNCF)

| Outil | Rôle | Statut CNCF |
|---|---|---|
| Argo CD | GitOps | Graduated |
| Trivy Operator | Audit sécurité | CNCF (Aqua, validé) |
| Falco | Détection runtime | Graduated |
| Kyverno | Policy-as-code | Graduated |
| Prometheus | Observabilité | Graduated |
| AI Endpoints | IA générative | OVHcloud |
