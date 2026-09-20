#!/usr/bin/env bash
# Deploy Quillbox: one Cloud Run service and two Cloud Run jobs, separated by what each is allowed to touch.
#
#   the adapter  (service quillbox,          qb-app@)      applies and reverts candidates; holds no key that
#                                                          can write a reading (round 140, P46)
#   the witness  (job-quillbox-witness,      qb-witness@)  the static tools only -- pyflakes and the AST
#                                                          compliance scan, which never run the candidate --
#                                                          holding the signing keys (round 141, P49)
#   the measure  (job-quillbox-measure,      qb-measure@)  pytest and coverage, which do run the candidate;
#                                                          holds no secret and no role, and delivers nothing
#
#   ./infra/deploy.sh iam          create the three service accounts and give the witness's the key; run once
#   ./infra/deploy.sh build        build the image
#   ./infra/deploy.sh service      deploy the adapter
#   ./infra/deploy.sh witness      create or update the witness job (static tools, holds the keys)
#   ./infra/deploy.sh measure      create or update the measure job (runs the candidate, holds nothing)
#   ./infra/deploy.sh keys-backup  copy .deploy-env.yaml into Secret Manager; losing it freezes the system
#   ./infra/deploy.sh check        print what proves each identity holds only what it should
#   ./infra/deploy.sh all          build, service, witness, measure
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$HERE/.."
PROJECT=${PROJECT:-acresgo-prod}; REGION=${REGION:-asia-south1}; REPO=${REPO:-cloud-run-source-deploy}
SERVICE=${SERVICE:-quillbox}; JOB="job-$SERVICE-witness"; MJOB="job-$SERVICE-measure"; SECRET=${SECRET:-QB_WITNESS_KEYS}
APP_SA="qb-app@$PROJECT.iam.gserviceaccount.com"
WITNESS_SA="qb-witness@$PROJECT.iam.gserviceaccount.com"
MEASURE_SA="qb-measure@$PROJECT.iam.gserviceaccount.com"
IMG="$REGION-docker.pkg.dev/$PROJECT/$REPO/$SERVICE"
OWL_BASE=${OWL_BASE:-https://owl-120680828302.asia-south1.run.app}

env_of () { grep -E "^$1:" "$ROOT/.deploy-env.yaml" | head -1 | sed -E 's/^[^:]+:[[:space:]]*"(.*)"$/\1/'; }
digest () { gcloud artifacts docker images describe "$IMG:latest" --project "$PROJECT" --format='value(image_summary.fully_qualified_digest)'; }

iam () {
  # Three accounts with no project roles at all; only the witness gets one binding, on one secret. Until this
  # ran, the adapter was the project default compute account, which holds editor -- and editor can add a version
  # to the witness's secret and redeploy the witness job. It cannot read the secret; it never needed to.
  for sa in qb-app qb-witness qb-measure; do
    gcloud iam service-accounts describe "$sa@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" >/dev/null 2>&1 ||
      gcloud iam service-accounts create "$sa" --project "$PROJECT" --display-name "Quillbox $sa"
  done
  gcloud secrets add-iam-policy-binding "$SECRET" --project "$PROJECT" \
    --member "serviceAccount:$WITNESS_SA" --role roles/secretmanager.secretAccessor >/dev/null
  for s in QB_ADAPTER_SECRET QB_PROPOSER_TOKEN; do
    gcloud secrets add-iam-policy-binding "$s" --project "$PROJECT" \
      --member "serviceAccount:$APP_SA" --role roles/secretmanager.secretAccessor >/dev/null 2>&1 || true
  done
  echo "qb-measure: no roles. qb-witness: $SECRET only. qb-app: its own two secrets only."
}

build () { ( cd "$ROOT" && gcloud builds submit --project "$PROJECT" --tag "$IMG:latest" . ); }

service () {
  # The point of this deploy is what is NOT here. Round 142: the two credentials it still needs are Secret
  # Manager references, not plain values -- `gcloud run services describe` hands a plain value to anything
  # holding run.services.get, which in this project includes three other graded tenants' runtime identity. And
  # the runtime key is gone: it is admitted on POST /cycle, so the graded application could advance the judge's
  # clock. The proposer token can read status and, on a one-option lever, propose nothing.
  gcloud run services update "$SERVICE" --project "$PROJECT" --region "$REGION" \
    --image "$IMG:latest" --service-account "$APP_SA" \
    --set-secrets "QB_ADAPTER_SECRET=QB_ADAPTER_SECRET:latest,QB_PROPOSER_TOKEN=QB_PROPOSER_TOKEN:latest" \
    --set-env-vars "QB_SID=$(env_of QB_SID),QB_OWL_BASE_URL=$OWL_BASE"
  echo "adapter live: $(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format='value(status.url)')"
}

witness () {
  # The job that holds the keys never runs the candidate. Round 141 probed the live job: the mounted secret is
  # mode 0444, world-readable, so any process in this container -- including the candidate's own code under
  # pytest -- could read all five private keys; and any process here can ask the metadata server for this
  # account's token and fetch the secret anyway. The boundary has to be the job, not the user. Pinned to an
  # image DIGEST, not a floating tag: :latest is writable by anything holding artifactregistry upload, and the
  # record would not show the swap.
  local img verb; img="$(digest)"
  if gcloud run jobs describe "$JOB" --project "$PROJECT" --region "$REGION" >/dev/null 2>&1; then verb=update; else verb=create; fi
  gcloud run jobs "$verb" "$JOB" --project "$PROJECT" --region "$REGION" \
    --image "$img" --service-account "$WITNESS_SA" --command python --args witness_job.py \
    --set-secrets "/secrets/witness-keys.json=$SECRET:latest" \
    --set-env-vars "QB_MODE=static,QB_SID=$(env_of QB_SID),QB_OWL_BASE_URL=$OWL_BASE,QB_IMAGE=$img,QB_VERSION=v1,QB_INDEX=0" \
    --max-retries 0 --task-timeout 900
  echo "witness job $JOB ready on $img"
}

measure () {
  # The job that runs the candidate holds nothing: no secret mounted, and qb-measure@ has no role anywhere, so
  # the metadata token any process here can always obtain opens nothing. It prints what it measured and
  # delivers nothing, because a number produced by running the candidate is within the candidate's reach.
  local img verb; img="$(digest)"
  if gcloud run jobs describe "$MJOB" --project "$PROJECT" --region "$REGION" >/dev/null 2>&1; then verb=update; else verb=create; fi
  gcloud run jobs "$verb" "$MJOB" --project "$PROJECT" --region "$REGION" \
    --image "$img" --service-account "$MEASURE_SA" --command python --args witness_job.py \
    --set-env-vars "QB_MODE=dynamic,QB_IMAGE=$img,QB_VERSION=v1,QB_INDEX=0" \
    --max-retries 0 --task-timeout 900
  echo "measure job $MJOB ready on $img; it holds no key and delivers nothing"
}

keys-backup () {
  # .deploy-env.yaml holds system F's owner key, and OWL stores only its hash: lose the file and the system is
  # frozen forever -- no Definition change, no connector, no cycle, no recovery (P47). Two of this platform's
  # own test tenants are already in exactly that state, because their onboarding script printed the keys
  # instead of writing them. This copies the file into Secret Manager, where only the operator can read it.
  gcloud secrets describe QB_OWNER_ENV --project "$PROJECT" >/dev/null 2>&1 &&
    gcloud secrets versions add QB_OWNER_ENV --project "$PROJECT" --data-file "$ROOT/.deploy-env.yaml" ||
    gcloud secrets create QB_OWNER_ENV --project "$PROJECT" --data-file "$ROOT/.deploy-env.yaml"
  echo "owner environment backed up to secret QB_OWNER_ENV in $PROJECT"
}

check () {
  echo "== the adapter: its identity, and every variable it holds =="
  gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" \
    --format="value(spec.template.spec.serviceAccountName, spec.template.spec.containers[0].env[].name)"
  echo "== the witness: holds the keys, must never run the candidate (QB_MODE=static) =="
  gcloud run jobs describe "$JOB" --project "$PROJECT" --region "$REGION" \
    --format="value(spec.template.spec.template.spec.serviceAccountName, spec.template.spec.template.spec.containers[0].image, spec.template.spec.template.spec.containers[0].env)"
  echo "== the measure job: runs the candidate, must hold no secret volume =="
  gcloud run jobs describe "$MJOB" --project "$PROJECT" --region "$REGION" \
    --format="value(spec.template.spec.template.spec.serviceAccountName, spec.template.spec.template.spec.volumes)"
}

case "${1:-all}" in
  iam) iam ;;
  build) build ;;
  service) service ;;
  witness) witness ;;
  measure) measure ;;
  keys-backup) keys-backup ;;
  check) check ;;
  all) build; service; witness; measure ;;
  *) echo "Usage: $0 [iam|build|service|witness|measure|keys-backup|check|all]" >&2; exit 1 ;;
esac
