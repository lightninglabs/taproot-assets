-- The declared_known flag indicates that this script key was explicitly
-- imported as a key that is relevant to this node, either when creating an
-- address or using the assetwalletrpc.DeclareScriptKey RPC. This will cause
-- assets with that script key to be included in the node's balance.
ALTER TABLE script_keys ADD COLUMN declared_known BOOLEAN;
