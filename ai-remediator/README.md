# AI Remediator

Couche IA de la chaîne : lit les `VulnerabilityReports` de Trivy Operator,
demande un correctif à AI Endpoints OVHcloud, ouvre une PR sur le dépôt GitOps.

## Lancer

```bash
export OVH_AI_ENDPOINTS_ACCESS_TOKEN=...   # clé du bundle équipe
export GITHUB_TOKEN=ghp_...                # token avec scope repo
export GITHUB_REPO=equipe8/gitops-repo
export KUBECONFIG=../kubeconfig-equipe-8.yaml

python remediator.py          # un cycle
python remediator.py --watch  # surveillance continue
```

Aucune dépendance externe (stdlib Python uniquement + kubectl).
