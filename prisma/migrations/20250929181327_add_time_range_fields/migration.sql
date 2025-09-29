/*
  Warnings:

  - Added the required column `endedAt` to the `ListeningSession` table without a default value. This is not possible if the table is not empty.
  - Added the required column `startedAt` to the `ListeningSession` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "public"."ListeningSession" ADD COLUMN     "clientAt" TIMESTAMP(3),
ADD COLUMN     "endedAt" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "source" TEXT,
ADD COLUMN     "startedAt" TIMESTAMP(3) NOT NULL;

-- CreateIndex
CREATE INDEX "ListeningSession_userId_startedAt_idx" ON "public"."ListeningSession"("userId", "startedAt");

-- CreateIndex
CREATE INDEX "ListeningSession_latitude_longitude_startedAt_idx" ON "public"."ListeningSession"("latitude", "longitude", "startedAt");
