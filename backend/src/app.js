import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import multer from "multer";
import mongoose from "mongoose";
import { config } from "./config.js";
import api from "./routes/index.js";
import { ApiError } from "./utils/ApiError.js";

export const app = express();

app.set("trust proxy", 1);
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(cookieParser());

// Uploaded media. express.static honours Range headers, so videos stream and seek.
app.use("/uploads", express.static(config.uploadsDir, { maxAge: "7d", fallthrough: false }));

app.get("/", (_req, res) => res.json({ name: "Kinora API", docs: "/api/v1/healthcheck" }));
app.use("/api/v1", api);

app.use((req, _res, next) => next(new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`)));

// Central error handler — every error becomes { success:false, message, errors }
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  let status = err.statusCode || err.status || 500;
  let message = err.message || "Internal server error";
  let errors = err.errors || [];

  if (err instanceof multer.MulterError) {
    status = 400;
    message = err.code === "LIMIT_FILE_SIZE" ? "File is too large" : err.message;
  } else if (err instanceof mongoose.Error.ValidationError) {
    status = 400;
    errors = Object.values(err.errors).map((e) => e.message);
    message = errors[0] || "Validation failed";
  } else if (err instanceof mongoose.Error.CastError) {
    status = 400;
    message = `Invalid ${err.path}`;
  } else if (err?.code === 11000) {
    status = 409;
    message = `${Object.keys(err.keyValue || {}).join(", ") || "Value"} already exists`;
  }

  if (status >= 500) console.error(err);
  res.status(status).json({ success: false, statusCode: status, message, errors: Array.isArray(errors) ? errors : [] });
});
