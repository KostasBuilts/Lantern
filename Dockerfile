# Lantern backend: ingest API, dashboard, AI gateway.
FROM node:22-slim
ENV NODE_ENV=production LANTERN_DB=/data/lantern.db PORT=8080
WORKDIR /app/backend
COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev
COPY backend/ ./
COPY public/ /app/public/
COPY config/ /app/config/
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 8080
HEALTHCHECK CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
