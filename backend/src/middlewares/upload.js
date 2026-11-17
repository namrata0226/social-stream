import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";
import { config } from "../config.js";
import { ApiError } from "../utils/ApiError.js";

for (const dir of ["videos", "images"]) fs.mkdirSync(path.join(config.uploadsDir, dir), { recursive: true });

const isVideoField = (field) => field === "videoFile";

const storage = multer.diskStorage({
  destination: (_req, file, cb) =>
    cb(null, path.join(config.uploadsDir, isVideoField(file.fieldname) ? "videos" : "images")),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, "");
    cb(null, `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext}`);
  },
});

const fileFilter = (_req, file, cb) => {
  const wantsVideo = isVideoField(file.fieldname);
  const valid = wantsVideo ? file.mimetype.startsWith("video/") : file.mimetype.startsWith("image/");
  if (valid) cb(null, true);
  else cb(new ApiError(400, `${file.fieldname} must be ${wantsVideo ? "a video" : "an image"} file`));
};

export const upload = multer({ storage, fileFilter, limits: { fileSize: config.maxUploadBytes } });
