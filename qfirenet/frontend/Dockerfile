# ─────────────────────────────────────────────────────────────────────────────
# QFireNet Frontend Dockerfile
# Two-stage build:
#   Stage 1 (builder): Node 20 — install deps and build the Vite production bundle
#   Stage 2 (serve):   nginx:alpine — serve the static bundle (tiny image, ~25MB)
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first (cached unless package.json changes)
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source and build
COPY . .

# VITE_API_URL: points to the backend service inside Docker Compose network
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build
# Output is in /app/dist/


# ── Stage 2: Serve with nginx ─────────────────────────────────────────────────
FROM nginx:alpine

# Copy built files from Stage 1
COPY --from=builder /app/dist /usr/share/nginx/html

# nginx config: redirect all routes to index.html for React Router (client-side routing)
RUN echo 'server { \
    listen 80; \
    root /usr/share/nginx/html; \
    index index.html; \
    location / { try_files $uri $uri/ /index.html; } \
    location /api/ { \
        proxy_pass http://backend:8000/; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
