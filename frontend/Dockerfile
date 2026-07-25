FROM node:22-bookworm-slim

RUN mkdir -p /app && chown node:node /app

USER node
WORKDIR /app

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

ARG VITE_API_BASE_URL=http://localhost:8000
RUN VITE_API_BASE_URL="$VITE_API_BASE_URL" npm run build

EXPOSE 4173

CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "4173", "--strictPort"]
