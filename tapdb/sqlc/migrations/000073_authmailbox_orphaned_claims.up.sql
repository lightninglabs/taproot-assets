-- Deleting a mailbox message used to delete its row while leaving the row
-- claiming its outpoint in place. A resend of such a message could then
-- neither be stored nor be recognized as one already delivered. Deleted
-- messages now keep their row, so drop the claims left without one: a resend
-- for their outpoint is then stored as a new message.
DELETE FROM tx_proof_claimed_outpoints
WHERE outpoint NOT IN (
    SELECT claimed_outpoint FROM authmailbox_messages
);
