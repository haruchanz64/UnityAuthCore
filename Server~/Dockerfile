FROM node:22-alpine

WORKDIR /app

COPY src/ ./src/

RUN mkdir -p /app/data && chown -R node:node /app

USER node

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    DATA_FILE=/app/data/auth-store.json

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

CMD ["node", "src/server.mjs"]
