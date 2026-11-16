# Runs the agents behind the ADK web server, on Gemini through Vertex AI.
# Deploy with ./deploy/cloudrun.sh.
FROM python:3.12-slim

WORKDIR /app
# Exact versions, wheels only (see deploy/image-requirements.txt). Unpinned, pip
# backtracked to a pandas that needs a C compiler, which this image lacks.
COPY deploy/image-requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements.txt

COPY . .
RUN python data/seed.py

# The sponsor is fixed per container in this demo. A real deployment binds it
# from the authenticated user (for example the IAP identity header).
ENV FDE_USER=pnair \
    FDE_MODEL=gemini-3-flash-preview \
    FDE_TOOLS=direct \
    FDE_RETRIEVER=lexical \
    GOOGLE_GENAI_USE_VERTEXAI=TRUE \
    PORT=8080

# The service is private and opened through `gcloud run services proxy`, which
# serves it at http://localhost:8080 but forwards the run.app host. ADK refuses
# a browser Origin that differs from the Host, so the proxy's origin is allowed.
CMD ["sh", "-c", "adk web --host 0.0.0.0 --port ${PORT} --allow_origins http://localhost:8080 ."]
