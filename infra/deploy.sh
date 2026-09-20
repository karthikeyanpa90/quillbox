#!/usr/bin/env bash
# Deploy Quillbox: one Cloud Run service (the adapter) and one Cloud Run Job (the witness). They share one image
# and one repository, and nothing else -- different identities, different permissions, and only one of them holds
# a key that can write a reading into OWL (round 140, P46).
#
#   ./infra/deploy.sh iam        create the two service accounts and give the witness's the key; run once
#   ./infra/deploy.sh build      build the image
#   ./infra/deploy.sh service    deploy the adapter (no connector secrets, no owner key, no witness)
#   ./infra/deploy.sh witness    create or update the witness job
#   ./infra/deploy.sh keys-backup  copy .deploy-env.yaml into Secret Manager; losing it freezes the system
#   ./infra/deploy.sh check      print the one command that proves the adapter holds nothing it shouldn't
#   ./infra/deploy.sh all        build, service, witness
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$HERE/.."
PROJECT=${PROJECT:-acresgo-prod}; REGION=${REGION:-asia-south1}; REPO=${REPO:-cloud-run-source-deploy}
SERVICE=${SERVICE:-quillbox}; JOB="job-$SERVICE-witness"; SECRET=${SECRET:-QB_WITNESS_KEYS}
APP_SA="qb-app@$PROJECT.iam.gserviceaccount.com"
WITNESS_SA="qb-witness@$PROJECT.iam.gserviceaccount.com"
IMG="$REGION-docker.pkg.dev/$PROJECT/$REPO/$SERVICE"
OWL_BASE=${OWL_BASE:-https://owl-120680828302.asia-south1.run.app}

env_of () { grep -E "^$1:" "$ROOT/.deploy-env.yaml" | head -1 | sed -E 's/^[^:]+:[[:space:]]*"(.*)"$/\1/'; }

iam () {
  # Two accounts with no project roles at all. The adapter needs no Google API: it serves HTTP and calls OWL.
  # This is the part that makes the independence claim true rather than aspirational -- until it runs, the
  # adapter runs as the default compute account, which holds roles/editor, and roles/editor can add a version to
  # the witness's secret and redeploy the witness job. It cannot read the secret, but it never needed to.
  for sa in qb-app qb-witness; do
    gcloud iam service-accounts describe "$sa@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" >/dev/null 2>&1 ||
      gcloud iam service-accounts create "$sa" --project "$PROJECT" \
        --display-name "$( [ "$sa" = qb-app ] && echo 'Quillbox adapter (no permissions)' || echo 'Quillbox witness (reads its own signing keys)' )"
  done
  gcloud secrets add-iam-policy-binding "$SECRET" --project "$PROJECT" \
    --member "serviceAccount:$WITNESS_SA" --role roles/secretmanager.secretAccessor >/dev/null
  echo "qb-app: no roles. qb-witness: secretAccessor on $SECRET only."
}
build () { ( cd "$ROOT" && gcloud builds submit --project "$PROJECT" --tag "$IMG:latest" . ); }
service () {
  # --clear-secrets and an explicit --set-env-vars: the point of this deploy is what is NOT here.
  gcloud run services update "$SERVICE" --project "$PROJECT" --region "$REGION" \
    --image "$IMG:latest" --service-account "$APP_SA" --clear-secrets \
    --set-env-vars "QB_SID=$(env_of QB_SID),QB_RUNTIME_KEY=$(env_of QB_RUNTIME_KEY),QB_ADAPTER_SECRET=$(env_of QB_ADAPTER_SECRET),QB_OWL_BASE_URL=$OWL_BASE"
  echo "adapter live: $(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format='value(status.url)')"
}
witness () {
  if gcloud run jobs describe "$JOB" --project "$PROJECT" --region "$REGION" >/dev/null 2>&1; then verb=update; else verb=create; fi
  # The keys are a mounted FILE, not an environment variable: the environment is inherited by every subprocess,
  # and one of those subprocesses runs the candidate's own code under pytest.
  gcloud run jobs $verb "$JOB" --project "$PROJECT" --region "$REGION" \
    --image "$IMG:latest" --service-account "$WITNESS_SA" --command python --args witness_job.py \
    --set-secrets "/secrets/witness-keys.json=$SECRET:latest" \
    --set-env-vars "QB_SID=$(env_of QB_SID),QB_OWL_BASE_URL=$OWL_BASE,QB_IMAGE=$IMG:latest,QB_VERSION=v1,QB_INDEX=0" \
    --max-retries 0 --task-timeout 900
  echo "witness job $JOB ready; QB_VERSION and QB_INDEX are overridden per execution"
}
keys-backup () {
  # .deploy-env.yaml holds system F's owner key, and OWL stores only its hash: lose the file and the system is
  # frozen forever -- no Definition change, no connector, no cycle, no recovery. Two of this platform's own test
  # tenants (Cartway, Fairline) are already in exactly that state, because their onboarding script printed the
  # keys instead of writing them. This copies the file into Secret Manager, where only the operator can read it.
  gcloud secrets describe QB_OWNER_ENV --project "$PROJECT" >/dev/null 2>&1 &&
    gcloud secrets versions add QB_OWNER_ENV --project "$PROJECT" --data-file "$ROOT/.deploy-env.yaml" ||
    gcloud secrets create QB_OWNER_ENV --project "$PROJECT" --data-file "$ROOT/.deploy-env.yaml"
  echo "owner environment backed up to secret QB_OWNER_ENV in $PROJECT"
}
check () {
  echo "== the adapter's identity and environment (nothing here may write a reading) =="
  gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" \
    --format="value(spec.template.spec.serviceAccountName, spec.template.spec.containers[0].env[].name)"
  echo "== the witness job's identity =="
  gcloud run jobs describe "$JOB" --project "$PROJECT" --region "$REGION" \
    --format="value(spec.template.spec.template.spec.serviceAccountName)"
}

case "${1:-all}" in
  iam) iam ;;
  build) build ;;
  service) service ;;
  witness) witness ;;
  keys-backup) keys-backup ;;
  check) check ;;
  all) build; service; witness ;;
  *) echo "Usage: $0 [iam|build|service|witness|check|all]" >&2; exit 1 ;;
esac
