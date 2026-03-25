FROM node:24-bullseye-slim

WORKDIR /app

# better-sqlite3: preferir prebuild (evita gcc/g++/python y reduce RAM en el build de Coolify).
ENV npm_config_build_from_source=false

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 80

ENV NODE_ENV=production

CMD ["node", "index.js"]
