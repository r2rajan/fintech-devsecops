#!/usr/bin/env bash
# One-shot setup and deployment for the Secure Supply Chain demo.
# Run this once before the presentation.
set -euo pipefail

PROJECT_ID="${1:-}"
REGION="${2:-europe-west2}"

if [ -z "$PROJECT_ID" ]; then
  echo "Usage: bash scripts/deploy.sh <PROJECT_ID> [REGION]"
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Project: $PROJECT_ID   Region: $REGION"

# ── APIs ──────────────────────────────────────────────────────────────────────
echo "==> Enabling APIs..."
gcloud services enable \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  containeranalysis.googleapis.com \
  run.googleapis.com \
  containerscanning.googleapis.com \
  storage.googleapis.com \
  --project="$PROJECT_ID" --quiet

# ── Artifact Registry ─────────────────────────────────────────────────────────
echo "==> Creating Artifact Registry repository..."
gcloud artifacts repositories create fintech-apps \
  --repository-format=docker \
  --location="$REGION" \
  --description="Secure supply chain demo" \
  --project="$PROJECT_ID" 2>/dev/null || echo "  (already exists)"

# ── Auth ──────────────────────────────────────────────────────────────────────
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

# ── Grant Cloud Build access ──────────────────────────────────────────────────
echo "==> Configuring Cloud Build IAM..."
CB_SA="$(gcloud projects describe "$PROJECT_ID" \
  --format='value(projectNumber)')@cloudbuild.gserviceaccount.com"

for role in roles/run.admin roles/artifactregistry.writer \
            roles/iam.serviceAccountUser containeranalysis.occurrences.editor \
            roles/storage.admin; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${CB_SA}" --role="$role" --quiet 2>/dev/null || true
done

# ── Trigger the pipeline ──────────────────────────────────────────────────────
echo "==> Submitting Cloud Build..."
gcloud builds submit "$HERE" \
  --config="$HERE/cloudbuild.yaml" \
  --project="$PROJECT_ID" \
  --substitutions="_REGION=${REGION}"

# ── Print URLs ────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
APP_URL=$(gcloud run services describe payment-risk-service \
  --project="$PROJECT_ID" --region="$REGION" \
  --format="value(status.url)" 2>/dev/null || echo "not deployed")
DASH_URL=$(gcloud run services describe supply-chain-dashboard \
  --project="$PROJECT_ID" --region="$REGION" \
  --format="value(status.url)" 2>/dev/null || echo "not deployed")
echo "  Payment Risk App : $APP_URL"
echo "  Executive Dashboard : $DASH_URL"
echo "═══════════════════════════════════════════════════"
