import fs from "fs";
import path from "path";
import mongoose from "mongoose";
import { config } from "./config.js";

let memoryServer = null;

export async function connectDB() {
  let uri = config.mongoUri;

  if (!uri && config.isVercel) throw new Error("MONGODB_URI is not set. Add your MongoDB Atlas connection string in the Vercel project settings.");

  if (!uri) {
    // Zero-setup local development: an embedded MongoDB whose data persists in backend/data/db
    const { MongoMemoryServer } = await import("mongodb-memory-server");
    const dbPath = path.join(config.dataDir, "db");
    fs.mkdirSync(dbPath, { recursive: true });
    memoryServer = await MongoMemoryServer.create({
      // 7.0 runs on older macOS (8.x needs macOS 14+); override with MONGOMS_VERSION
      binary: { version: process.env.MONGOMS_VERSION || "7.0.14" },
      instance: { dbPath, storageEngine: "wiredTiger", port: 27027 },
    });
    uri = memoryServer.getUri();
    console.log(`🗄️  Using embedded MongoDB (data: ${dbPath})`);
  }

  await mongoose.connect(uri, { dbName: config.dbName });
  console.log("✅ MongoDB connected");
}

export async function disconnectDB() {
  await mongoose.disconnect();
  if (memoryServer) await memoryServer.stop({ doCleanup: false });
}
