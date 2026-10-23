FROM node:20-slim

WORKDIR /app

# Install all dependencies (including devDependencies for build)
COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

# Remove devDependencies after build
RUN npm prune --omit=dev

# Create data directory for token storage
RUN mkdir -p /app/data

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV DATA_DIR=/app/data

EXPOSE 3000

CMD ["node", "dist/index.js"]
