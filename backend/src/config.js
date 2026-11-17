import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, "..");
dotenv.config({ path: path.join(ROOT_DIR, ".env") });

const isProd = process.env.NODE_ENV === "production";
// Vercel runs the API as serverless functions: read-only disk except /tmp, nothing persists between requests
const isVercel = Boolean(process.env.VERCEL);

export const config = {
  isProd,
  isVercel,
  port: Number(process.env.PORT) || 8000,
  corsOrigin: (process.env.CORS_ORIGIN || "http://localhost:5173").split(",").map((s) => s.trim()),
  mongoUri: process.env.MONGODB_URI || "",
  dbName: process.env.DB_NAME || "socialstream",
  accessSecret: process.env.ACCESS_TOKEN_SECRET || "dev-access-secret",
  accessExpiry: process.env.ACCESS_TOKEN_EXPIRY || "1d",
  refreshSecret: process.env.REFRESH_TOKEN_SECRET || "dev-refresh-secret",
  refreshExpiry: process.env.REFRESH_TOKEN_EXPIRY || "10d",
  uploadsDir: isVercel ? "/tmp/kinora-uploads" : path.join(ROOT_DIR, "uploads"),
  dataDir: path.join(ROOT_DIR, "data"),
  maxUploadBytes: (Number(process.env.MAX_UPLOAD_MB) || 1024) * 1024 * 1024,
  cloudinary: {
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  },
};

export const useCloudinary = Boolean(
  config.cloudinary.cloud_name && config.cloudinary.api_key && config.cloudinary.api_secret
);

if (isProd && (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET)) {
  throw new Error("ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET must be set in production");
}
