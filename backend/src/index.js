import { config } from "./config.js";
import { connectDB, disconnectDB } from "./db.js";
import { app } from "./app.js";

try {
  await connectDB();
  if (process.env.SEED_DEMO !== "false") {
    const { seedDemo } = await import("./seed.js");
    await seedDemo().catch((err) => console.warn("Demo seed skipped:", err.message));
  }
  const server = app.listen(config.port, () => {
    console.log(`🚀 API running at http://localhost:${config.port}`);
  });

  const shutdown = async () => {
    server.close();
    await disconnectDB();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
} catch (err) {
  console.error("❌ Failed to start server:", err);
  process.exit(1);
}
