FROM node:24-bullseye-slim

WORKDIR /app

# build tools for native deps (better-sqlite3)
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 80

ENV NODE_ENV=production

CMD ["node", "index.js"]

