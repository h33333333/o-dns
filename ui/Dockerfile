FROM node:22-slim AS base
WORKDIR /app

FROM base AS deps
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store pnpm fetch --frozen-lockfile
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile --prod

FROM base AS build
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store pnpm fetch --frozen-lockfile
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile
COPY . .
ARG API_SERVER_URL
RUN VITE_API_SERVER_URL=${API_SERVER_URL} pnpm build

FROM base
COPY --from=build /app/dist /app/dist
EXPOSE 80
RUN npm install -g serve
RUN groupadd -g 2000 app && useradd -m -u 2001 -g app app
USER app
CMD [ "serve", "-s", "dist", "-p", "80"]
