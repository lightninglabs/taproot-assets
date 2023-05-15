# Taproot Assets in Docker

## Requirements
- Docker
- git
- a running lnd node

## Building from Source
```
git clone https://github.com/lightninglabs/taproot-assets
cd taproot-assets
docker build -f dev.Dockerfile -t taproot-assets .
```

## Starting Docker Container
### Quick Startup
```
docker run --name taproot-assets --rm -v /PATH/TO_YOUR/LND/:/root/.lnd/:ro -v /PATH/TO:YOUR/TAPD/:/root/.tapd/ --net=host tapd --network=testnet --debuglevel=debug --lnd.host=localhost:10009 --lnd.macaroonpath=/root/.lnd/data/chain/bitcoin/testnet/admin.macaroon --lnd.tlspath=/root/.lnd/tls.cert
```

