#!/bin/bash

# Protos for services that tapd consumes as a client rather than serves.
# They must not expose REST bindings, so their yaml annotations are
# intentionally empty and this check is skipped for them.
CLIENT_ONLY=(
  "./priceoraclerpc/price_oracle.proto"
  "./portfoliopilotrpc/portfolio_pilot.proto"
)

for proto in $(find . -name "*.proto"); do
  skip=0
  for exempt in "${CLIENT_ONLY[@]}"; do
    if [ "$proto" = "$exempt" ]; then
      skip=1
      break
    fi
  done
  if [ "$skip" -eq 1 ]; then
    continue
  fi

  for rpc in $(awk '/    rpc /{print $2}' "$proto"); do
    yaml=${proto%%.proto}.yaml
    if ! grep -q "$rpc" "$yaml"; then
      echo "RPC $rpc not added to $yaml file"
      exit 1
    fi
  done
done
