# Runs the agents behind the ADK web server, on Gemini through Vertex AI.
# Deploy with ./deploy/cloudrun.sh. NOTE: written but not yet built or
# deployed; treat the first deploy as a test.
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir "google-adk[extensions,mcp]>=2.0" python-dotenv

COPY . .
RUN python data/seed.py

# The sponsor is fixed per container in this demo. A real deployment binds it
# from the authenticated user (for example the IAP identity header).
ENV FDE_USER=pnair \
    FDE_MODEL=gemini-2.5-flash \
    FDE_TOOLS=direct \
    FDE_RETRIEVER=lexical \
    GOOGLE_GENAI_USE_VERTEXAI=TRUE \
    PORT=8080

CMD ["sh", "-c", "adk web --host 0.0.0.0 --port ${PORT} ."]
