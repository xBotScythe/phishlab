-- CreateTable
CREATE TABLE "AnalysisRun" (
    "id" TEXT NOT NULL,
    "url" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "folder" TEXT NOT NULL,
    "report" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "hasScreenshot" BOOLEAN NOT NULL DEFAULT false,
    "error" TEXT,

    CONSTRAINT "AnalysisRun_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FeedStatus" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "active" BOOLEAN NOT NULL DEFAULT false,
    "lastRun" TIMESTAMP(3),
    "batchSize" INTEGER NOT NULL DEFAULT 5,

    CONSTRAINT "FeedStatus_pkey" PRIMARY KEY ("id")
);
