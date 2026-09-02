-- Distinguish the two reasons an asset transfer is superseded.
--
-- The superseded flag has carried two incompatible meanings. A
-- transfer superseded by SupersedeConflictingTransfers lost a race to
-- a rival local form and is revivable: if the rival is later abandoned
-- and no confirmed transfer claims the input, the loser becomes live
-- again. A transfer superseded by MarkTransferSuperseded is
-- permanently dead — its inputs were claimed by a buried foreign
-- transaction, so its own anchor can never confirm.
--
-- UnsupersedeSafeTransfers reverses the flag and could not tell these
-- apart, so abandoning one transfer resurrected a permanently dead
-- sibling that shared an input. The revived transfer is then resumed
-- at startup and rebroadcasts an anchor that can never confirm.
--
-- The abandoned column records the second case. Existing rows default
-- to false: a transfer superseded before this migration was either a
-- live rivalry loser (correctly revivable) or already dead and
-- unreferenced, and no backfill can recover which.

ALTER TABLE asset_transfers
    ADD COLUMN abandoned BOOLEAN NOT NULL DEFAULT FALSE;
