-- Phase 8: remember whether detection ran on a batch, so events stored before a
-- crash (or before a batch failed half-way) are still checked by the rules.
--   NULL      detection has not run yet (new batches, interrupted ones)
--   'done'    detection ran on every stored chunk
--   'skipped' ingested with `threatlens ingest --no-detect`
ALTER TABLE ingest_batches ADD COLUMN detection TEXT
    CHECK (detection IS NULL OR detection IN ('done', 'skipped'));
-- Batches from before this migration were handled by the old code path.
UPDATE ingest_batches SET detection = 'done';
CREATE INDEX ingest_batches_detection ON ingest_batches(id) WHERE detection IS NULL;
