FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy application source code and data
COPY . .

# Build frontend production bundle into dist/
RUN npm run build

# Expose default HTTP port
EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

# Container healthcheck against live health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/api/health || exit 1

# Launch persistent Express + Vite static server
CMD ["npm", "start"]
