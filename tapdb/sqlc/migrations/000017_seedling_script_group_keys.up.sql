-- According to SQLite docs, a column added via ALTER TABLE cannot be both
-- a REFERENCE and NOT NULL, so we'll have to enforce non-nilness outside of the DB.
ALTER TABLE asset_seedlings ADD COLUMN script_key_id BIGINT REFERENCES script_keys(script_key_id);

-- For a group anchor, we derive the internal key for the future group key early,
-- to allow use of custom group witnesses.
ALTER TABLE asset_seedlings ADD COLUMN group_internal_key_id BIGINT REFERENCES internal_keys(key_id);

-- For a group key, the internal key can also be tweaked to commit to a
-- tapscript tree. Once we finalize the batch, this tweak will also be stored
-- as part of the asset group itself.
ALTER TABLE asset_seedlings ADD COLUMN group_tapscript_root BLOB;