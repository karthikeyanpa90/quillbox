# Quillbox: a standalone tenant, deployed the same way every other one here is. One image serves two very
# different things -- the adapter (service.py, run as the Cloud Run service) and the witness (witness_job.py, run
# as a Cloud Run Job under its own identity). One image on purpose: candidates/ and tests/ then cannot drift
# between what is served and what is measured. Sharing an image shares no privilege: what each can do is set by
# the service account it runs as and the secret mounted into it, not by what is on disk.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py service.py witness.py witness_job.py qb_signing.py qb_digest.py qb_env.py ./
COPY quillbox_app ./quillbox_app
COPY candidates ./candidates
COPY tests ./tests
ENV PORT=8080
CMD ["sh", "-c", "python -m uvicorn service:app --host 0.0.0.0 --port ${PORT}"]
