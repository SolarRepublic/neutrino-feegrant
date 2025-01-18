# syntax=docker/dockerfile:1

# === Dependencies stage
FROM node:22-bookworm-slim AS deps

# system dependencies
RUN apt-get update && \
	apt-get upgrade -y

# install pnpm
RUN npm i -g pnpm

# set working dir
WORKDIR /usr/src/app

# copy package descriptors and any dependency patches 
COPY package.json pnpm-lock.yaml ./
COPY patche[s] ./patches

# install dependencis from lockfile
RUN pnpm i --frozen-lockfile


# === Build stage
FROM deps AS build

# set working dir
WORKDIR /usr/src/app

# copy installed node_modules from deps image
COPY --from=deps /usr/src/app/node_modules ./node_modules

# copy package for build script and possible TypeScript configs
COPY package.json ./

# tsconfig needed to build TypeScript
COPY tsconfig.json ./

# copy source code
COPY ./src ./src

# build application
RUN pnpm run build-app


# === Production stage
FROM build AS prod

# set working dir
WORKDIR /usr/src/app

# create empty .env file
RUN touch .env

# copy package for run script
COPY package.json ./

# copy installed node_modules from build image
COPY --from=build /usr/src/app/node_modules ./node_modules

# copy built assets
COPY --from=build /usr/src/app/dist ./dist

# TODO: use docker secret mounts
ENV SERVER_SK=""
ENV SECRET_LCD=""
ENV SECRET_LCD_REQUEST_ORIGIN_HEADER=""
ENV SECRET_RPC=""
ENV GAS_PRICE=""
ENV ALLOWANCE_AMOUNT=""
ENV FEEGRANT_MEMO=""
ENV FEEGRANT_GAS_LIMIT_GRANT=""
ENV FEEGRANT_GAS_LIMIT_REVOKE=""
ENV SERVER_HOST=""
ENV SERVER_PORT=""
ENV CHAIN_ID=""

CMD ["pnpm", "run", "start"]
ENTRYPOINT ["pnpm", "run", "start"]
