-- AlterTable
ALTER TABLE "deployments" ADD COLUMN     "isDemo" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "sessions" ADD COLUMN     "isDemo" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "deployment_policy_status" (
    "id" TEXT NOT NULL,
    "deploymentId" TEXT NOT NULL,
    "etag" TEXT NOT NULL,
    "appliedAt" TIMESTAMP(3) NOT NULL,
    "daemonVersion" TEXT,
    "applied" JSONB NOT NULL,
    "unsupported" JSONB NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "deployment_policy_status_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "deployment_policy_status_deploymentId_key" ON "deployment_policy_status"("deploymentId");

-- AddForeignKey
ALTER TABLE "deployment_policy_status" ADD CONSTRAINT "deployment_policy_status_deploymentId_fkey" FOREIGN KEY ("deploymentId") REFERENCES "deployments"("id") ON DELETE CASCADE ON UPDATE CASCADE;

