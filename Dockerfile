# Multi-stage Dockerfile for TrustGuard Node.js Web & API Service
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package manifests and install dependencies
COPY package*.json ./
RUN npm ci

# Copy source code and build client + server bundle
COPY . .
RUN npm run build

# Production runtime stage
FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

# Install production dependencies only
COPY package*.json ./
RUN npm ci --only=production

# Copy compiled bundles and public assets from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/documents ./documents

# Expose server port
EXPOSE 3000

# Start production server
CMD ["node", "dist/server.cjs"]
