# Hanzo Platform Mirror

This directory mirrors selected production manifests from:

- `/Users/z/work/hanzo/devops/k8s`

Purpose:

- Keep shared DOKS platform manifests visible in both `hanzo/devops` and `lux/devops`.
- Avoid config drift on shared ingress/KMS bot configuration.

Authoritative source:

- `hanzo/devops` remains source-of-truth for Hanzo platform services.

Sync:

```bash
/Users/z/work/lux/devops/scripts/sync-hanzo-devops.sh
```
