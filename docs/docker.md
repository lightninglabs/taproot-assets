# Taro in Docker

## Requirements
- Docker
- git
- a running lnd node

## Building from Source
```
git clone https://github.com/lightninglabs/taro
cd taro
docker build -f dev.Dockerfile -t taro .
```

## Starting Docker Container
### Quick Startup
```
docker run --name taro --rm -v /PATH/TO_YOUR/LND/:/root/.lnd/:ro -v /PATH/TO:YOUR/TARO/:/root/.taro/ --net=host taro --network=testnet --debuglevel=debug --lnd.host=localhost:10009 --lnd.macaroonpath=/root/.lnd/data/chain/bitcoin/testnet/admin.macaroon --lnd.tlspath=/root/.lnd/tls.cert
```

