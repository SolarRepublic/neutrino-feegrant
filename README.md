# Neutrino Feegrant

Simple, bare bones, performant Feegrant API built on [Neutrino](https://github.com/SolarRepublic/neutrino).

```sh
docker run --rm -t feegrant \
    -e SERVER_SK "${FEEGRANT_SECRET_KEY_HEX}" \
    -e SECRET_LCD=http://url-to-lcd \
    -e SECRET_RPC=http://url-to-rpc \
	 -e GAS_PRICE=0.1
	 -e ALLOWANCE_AMOUNT=50000
	 -e SERVER_HOST=0.0.0.0
	 -e SERVER_PORT=5000
    ghcr.io/solarrepublic/neutrino-feegrant:latest
```

## Using with docker-compose

Works well with the [Cosmos Sync Balancer](https://github.com/SolarRepublic/cosmos-sync-balancer):
```yaml
services:
  balancer:
    image: ghcr.io/solarrepublic/cosmos-sync-balancer:latest
    ports:
      - "8443:8443"
      - "23000:23000"
    volumes:
      - "./build/balancer-prod.json:/data/config.json"
  feegrant:
    image: ghcr.io/solarrepublic/neutrino-feegrant:latest
    depends_on:
      balancer:
        condition: service_healthy
    ports:
      - "5000:5000"
    environment:
      SERVER_SK: "${FEEGRANT_SECRET_KEY_HEX}"
      SECRET_LCD: http://balancer:8443/secret-lcd
      SECRET_RPC: http://balancer:8443/secret-rpc
      GAS_PRICE: 0.1
      ALLOWANCE_AMOUNT: 50000
      SERVER_HOST: 0.0.0.0
      SERVER_PORT: 5000
```

<!-- 
```console
$ bun install
$ cp .env.example .env
$ nano .env    # edit the .env file
$ bun run src/server.ts
``` -->
