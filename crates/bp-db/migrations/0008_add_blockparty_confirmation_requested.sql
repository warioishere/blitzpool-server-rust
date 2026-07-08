-- Admin-gated "members may now confirm their split" signal. Null until the
-- admin explicitly requests confirmation (a button next to Save Splits); the
-- member dashboard shows the "confirm your share" prompt only once this is set,
-- so a freshly-joined member isn't nagged before the admin has assigned splits.
ALTER TABLE blockparty_group
  ADD COLUMN IF NOT EXISTS "confirmationRequestedAt" BIGINT;
