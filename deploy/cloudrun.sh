#!/usr/bin/env bash
# Build and deploy the agents to Cloud Run, on Gemini through Vertex AI.
#
#   ./deploy/cloudrun.sh
#
# Reads .env. Needs GOOGLE_CLOUD_PROJECT; everything else has a default.
# No API key is sent to Cloud Run: the service account calls Vertex AI, so it
# needs the "Vertex AI User" role (roles/aiplatform.user).
#
# The service is deployed private (--no-allow-unauthenticated). The ADK web UI
# lets whoever can reach it drive the agents on your Vertex AI bill, so do not
# open it to the internet. Reach it with:
#   gcloud run services proxy "$SERVICE" --project "$GOOGLE_CLOUD_PROJECT" --region "$REGION"
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then set -a; . ./.env; set +a; fi

: "${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT in .env}"
REGION="${FDE_RUN_REGION:-us-central1}"
SERVICE="${FDE_SERVICE:-agent-gateway}"
VERTEX_LOCATION="${GOOGLE_CLOUD_LOCATION:-us-central1}"

gcloud run deploy "$SERVICE" \
  --source . \
  --project "$GOOGLE_CLOUD_PROJECT" \
  --region "$REGION" \
  --no-allow-unauthenticated \
  --memory 1Gi \
  --set-env-vars "GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_PROJECT=${GOOGLE_CLOUD_PROJECT},GOOGLE_CLOUD_LOCATION=${VERTEX_LOCATION},FDE_MODEL=${FDE_DEPLOY_MODEL:-gemini-2.5-flash},FDE_USER=${FDE_DEPLOY_USER:-pnair},FDE_TOOLS=${FDE_DEPLOY_TOOLS:-direct},FDE_RETRIEVER=lexical"

echo
echo "deployed. To open it:"
echo "  gcloud run services proxy $SERVICE --project $GOOGLE_CLOUD_PROJECT --region $REGION"
