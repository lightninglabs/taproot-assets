# Supply verifier

Expected flow:

```text

supply verifier flow:
 - issuer publishes supply commit
   - commit state machine informs verifier state machine
   - push to universe
   - component call flow:
      - issuer side:
          supplycommit.Manager -> supplySyncer.PushSupplyCommitment
      - universe side:
          rpcserver.InsertSupplyCommitment -> supplyverify.Manager.InsertSupplyCommit -> supplyCommitView.InsertSupplyCommit
 - user enables sync for asset
   - tell state machine to start syncing
   - state machine loops through local and remote supply commits
   - component call flow:
      - user side:
          supplycommit.Manager.SyncSupplyCommit -> supplyCommitView.FetchSupplyCommit -> loop to find last local known
                                                -> supplySyncer.FetchSupplyCommit -> rpc.FetchSupplyCommit
      - universe side:
          rpcserver.FetchSupplyCommit -> supplyverify.Manager.FetchSupplyCommit -> supplyCommitView.FetchSupplyCommit
```

TODO:
 - verify push flow in itest
 - finish implementing sync flow for asset group
   - triggered when a new asset group issuance proof is synced
   - algorithm:
      - find the last locally known supply commit
      - if not found, start at the very first (locator-type: very first)
      - if found, query by spent outpoint of last known to get next supply commit
      - if successful answer, repeat above
      - if error (detect ErrCommitmentNotFound), we know we're up to date
      - verification of supply commit:
         - .Verify() on parsed commitment
         - Query supply tree state at previous commit, apply all new leaves, verify that temporary root matches the one returned from server
         - if above succeeds, persist new leaves
