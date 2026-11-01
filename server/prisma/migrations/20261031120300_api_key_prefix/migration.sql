-- The prefix an API key was minted with. Keys that exist when this runs
-- were issued as av_srv_…; new keys are pv_srv_… and set it explicitly.
ALTER TABLE "api_keys" ADD COLUMN "tokenPrefix" TEXT NOT NULL DEFAULT 'av_srv_';
