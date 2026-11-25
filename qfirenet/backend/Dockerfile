# ─────────────────────────────────────────────────────────────────────────────
# QFireNet Backend Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Multi-stage builds are more efficient, but for clarity (this is a student
# project that must be explainable) we use a single-stage build.
#
# HOW DOCKER BUILDS WORK:
#   Each instruction creates a new "layer" in the image.  Docker caches layers,
#   so if requirements.txt hasn't changed, the pip install step is skipped on
#   rebuild — making subsequent builds much faster.
# ─────────────────────────────────────────────────────────────────────────────

# Base image: Python 3.11 on Debian Slim (smallest official Python image)
FROM python:3.11-slim

# ── System dependencies ───────────────────────────────────────────────────────
# libpq-dev: PostgreSQL C client headers (needed by psycopg2)
# gcc:       C compiler (some Python packages need it to build)
# We clean apt caches in the same RUN command to minimise layer size.
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*


# ── Set working directory inside the container ────────────────────────────────
WORKDIR /app

# ── Install Python dependencies ───────────────────────────────────────────────
# Copy requirements first — if requirements.txt doesn't change, Docker reuses
# the cached pip install layer on subsequent builds.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application source code ──────────────────────────────────────────────
COPY . .

# ── Expose the port uvicorn will listen on ────────────────────────────────────
EXPOSE 8000

# ── Start the FastAPI server ──────────────────────────────────────────────────
# --host 0.0.0.0: Listen on all interfaces (not just localhost) inside Docker.
# --port 8000:    Explicit port.
# --workers 1:    Single worker for dev; increase for production.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
