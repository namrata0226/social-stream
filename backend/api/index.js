// Vercel serverless entry. Locally the API runs from src/index.js instead.
// Every request is handled by the Express app; the DB connection is reused while the function stays warm.
import { app } from "../src/app.js";
import { connectDB } from "../src/db.js";

let ready = null;

export default async function handler(req, res) {
  try {
    ready ??= connectDB();
    await ready;
  } catch (err) {
    ready = null; // retry on the next request
    console.error("Database connection failed:", err);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify({ success: false, statusCode: 500, message: "Database connection failed" }));
  }
  return app(req, res);
}
