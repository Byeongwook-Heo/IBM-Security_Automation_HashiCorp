# EKS Fargate optimization recommendations

This directory provides recommendation-only collection for the `security-lab`
namespace. It does not deploy Karpenter, patch workload resources, evict pods, or
create external credentials.

## Data paths

- KRR reads workload metadata and Prometheus usage metrics, then emits a JSON
  report to the CronJob log.
- Goldilocks creates `VerticalPodAutoscaler` objects only for the labeled
  namespace. The VPA updater and admission webhook are disabled.
- The VPA collector reads the recommendation status and emits only workload and
  CPU/memory recommendation columns as TSV. Existing Loki or Elastic log
  forwarding can collect both CronJob outputs.

## Prerequisites

- The EKS Fargate profile selects `security-lab`.
- Prometheus 2.26 or newer, kube-state-metrics, and the KRR container usage
  metrics are available. Verify the Prometheus queries for
  `container_cpu_usage_seconds_total` and
  `container_memory_working_set_bytes` return Fargate pod data.
- The Kubernetes Metrics API is available (`kubectl top pods -n security-lab`).
  The values file deliberately does not install another metrics-server.
- The VPA 1.6.0 CRDs are installed before the Helm release. The Fairwinds VPA
  subchart deploys the recommender and RBAC, but it does not install the CRDs.
- Helm can reach `https://charts.fairwinds.com/stable` and the cluster can pull
  the pinned KRR and kubectl images.
- The existing log pipeline collects completed CronJob pod logs before the
  24-hour job TTL expires.

## Installation

```bash
kubectl apply -f k8s/optimization/goldilocks-namespace.example.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/vertical-pod-autoscaler-1.6.0/vertical-pod-autoscaler/deploy/vpa-v1-crd-gen.yaml

helm repo add fairwinds-stable https://charts.fairwinds.com/stable
helm repo update
helm upgrade --install goldilocks fairwinds-stable/goldilocks \
  --version 10.4.1 \
  --namespace security-lab \
  --values k8s/optimization/goldilocks-values.yaml \
  --wait

kubectl apply -f k8s/optimization/krr-rbac.example.yaml
kubectl apply -f k8s/optimization/krr-cronjob.example.yaml
kubectl apply -f k8s/optimization/vpa-recommendation-collector.example.yaml
```

`vpa-recommendation-only.example.yaml` is an optional example for a workload
managed without Goldilocks. Its update mode is `Off` and its recommendations
control requests only.

Trigger one-shot verification jobs without changing the schedules:

```bash
kubectl create job --from=cronjob/krr-recommendation-export \
  krr-recommendation-export-manual -n security-lab
kubectl create job --from=cronjob/vpa-recommendation-export \
  vpa-recommendation-export-manual -n security-lab
```

Read results from logs. Do not apply the recommendations automatically:

```bash
kubectl logs job/krr-recommendation-export-manual -n security-lab
kubectl logs job/vpa-recommendation-export-manual -n security-lab
```
