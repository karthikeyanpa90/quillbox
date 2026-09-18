# Quillbox: a standalone tenant, deployed the same way every other one here is -- one Cloud Run
# service, no import path back into OWL's own source. candidates/ ships inside the image so apply()
# can swap real code between real candidates without a network call.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py service.py witness.py ./
COPY quillbox_app ./quillbox_app
COPY candidates ./candidates
COPY tests ./tests
ENV PORT=8080
CMD ["sh", "-c", "python -m uvicorn service:app --host 0.0.0.0 --port ${PORT}"]
