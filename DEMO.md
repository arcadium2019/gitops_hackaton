# Scénario de démo — 10 min chrono (équipe 8)

## AVANT de passer (15 min avant, checklist)

- [ ] `$env:KUBECONFIG = "C:\...\kubeconfig-equipe-8.yaml"` dans CHAQUE terminal
- [ ] 3 port-forwards lancés dans 3 terminaux séparés :
  - Argo CD : `kubectl port-forward svc/argocd-server -n argocd 8080:443` → https://localhost:8080 (admin / PTXrMP4E89Dbc52h)
  - Grafana : `kubectl port-forward svc/kube-prometheus-stack-grafana -n monitoring 3000:80` (admin / hackathon2026)
  - Falco UI : `kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802:2802` (admin / admin)
- [ ] Onglets ouverts : GitHub (repo), Argo CD, Grafana (dashboard CVE), Falco UI
- [ ] **Réintroduire la faille** 20 min avant le passage (le temps que Trivy scanne) :
  ```
  git revert <sha-du-merge-PR3> --no-edit && git push
  ```
  → Argo CD redéploie nginx:1.14.2 privileged → Trivy regénère les rapports (~5 min)
- [ ] Vérifier : `kubectl get vulnerabilityreports -n demo` montre bien des CRITICAL
- [ ] Fermer toute PR encore ouverte (sinon le remediator skip)
- [ ] Plan B prêt : captures d'écran de chaque étape dans un dossier

## DÉROULÉ (10 min)

**1. L'architecture — 1 min** *(slide schéma)*
"Tout ce qui tourne sur le cluster vient de Git." Montrer l'UI Argo CD : 7 applications
Synced/Healthy — la stack elle-même (Trivy, Falco, Kyverno, Prometheus) est déployée
par Argo CD, pas à la main.

**2. La cible vulnérable — 1 min**
```
kubectl get vulnerabilityreports -n demo
```
"Trivy scanne en continu : 31 CVE CRITICAL sur legacy-web (nginx 2018, privileged, root)."
Montrer le compteur Grafana de CVE critiques.

**3. Kyverno + Falco — 1 min**
```
kubectl get policyreports -n demo
kubectl exec -it deploy/legacy-web -n demo -- sh -c "cat /etc/shadow"
```
"Kyverno signale privileged/root/limits. Et en runtime : je viens d'ouvrir un shell
dans le conteneur → alerte Falco en direct" (montrer la Falco UI).

**4. L'IA entre en scène — 2 min** ⭐
```
powershell -File run-remediator.ps1
```
Commenter pendant que ça tourne : "Le script lit les VulnerabilityReports, envoie
le manifeste + les CVE à AI Endpoints OVHcloud, et ouvre une Pull Request."
→ La PR s'ouvre en direct à l'écran.

**5. La revue humaine — 2 min** ⭐
Ouvrir la PR sur GitHub : lire l'explication de l'IA, montrer le diff
(image épinglée nginx-unprivileged, suppression privileged, non-root, limits).
"L'IA propose, l'humain valide — c'est le garde-fou." **Merger devant le jury.**

**6. Le cluster se corrige tout seul — 2 min**
UI Argo CD : vulnerable-workloads passe OutOfSync → Synced (forcer Refresh).
```
kubectl get pods -n demo
```
Nouveaux pods, images corrigées. "Au prochain scan, les compteurs tombent à zéro" —
montrer la courbe Grafana qui chute (celle du run précédent si le scan n'a pas fini).

**7. Conclusion — 1 min**
Tableau CNCF (slide). Limites assumées : mode Audit (choix démo), secrets en env vars
(piste ESO), un seul fichier remédié. Améliorations : CronJob in-cluster, dry-run
avant PR, alertes Falco → IA.

## Q/A probables (5 min)

- *Pourquoi Trivy et pas Kubescape ?* → CRD natives (`VulnerabilityReport`) faciles à consommer par le script.
- *Et si l'IA propose un correctif cassé ?* → C'est le rôle de la revue humaine ; piste : `kubectl apply --dry-run=server` avant d'ouvrir la PR.
- *Pourquoi Kyverno en Audit et pas Enforce ?* → En Enforce il bloquerait notre workload de démo ; en prod on passerait les policies critiques en Enforce.
- *Où sont les secrets ?* → Variables d'environnement hors Git ; en prod : External Secrets Operator (CNCF Incubating).
- *Ça marche pour d'autres workloads ?* → Oui, le remediator agrège tous les VulnerabilityReports du namespace ; extension naturelle : PolicyReports Kyverno et alertes Falco.

## Répartition de la parole (à adapter)

- Intro + archi (1-2) : membre GitOps
- Détection (3) : membre Détection/Runtime
- IA + PR + merge (4-5) : membre IA — le cœur, le plus à l'aise
- Sync + conclusion (6-7) : membre GitOps ou IA

## Rejouer la boucle (entre deux répétitions)

1. `git revert <sha-du-dernier-correctif> --no-edit && git push` → la faille revient
2. Attendre le scan Trivy (~5 min)
3. Relancer le remediator → nouvelle PR → merge → resync. Boucle infinie de démo.
