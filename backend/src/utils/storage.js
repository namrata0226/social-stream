import fs from "fs/promises";
import path from "path";
import { v2 as cloudinary } from "cloudinary";
import { config, useCloudinary } from "../config.js";
import { ApiError } from "./ApiError.js";

export const CLOUD_ROOT = "kinora";

if (useCloudinary) cloudinary.config(config.cloudinary);

/**
 * Persist a file that multer already wrote to backend/uploads/<folder>/.
 * Returns { url, public_id, provider }.
 *  - local:      served by express at /uploads/<folder>/<file> (HTTP range requests → seekable streaming)
 *  - cloudinary: uploaded, then the local copy is removed
 */
export async function persistFile(file) {
  if (!file) return null;
  const folder = path.basename(path.dirname(file.path));

  if (!useCloudinary && config.isVercel) {
    await fs.unlink(file.path).catch(() => {});
    throw new ApiError(500, "Uploads need Cloudinary on Vercel. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET.");
  }

  if (useCloudinary) {
    try {
      const res = await cloudinary.uploader.upload(file.path, {
        resource_type: file.mimetype.startsWith("video/") ? "video" : "image",
        folder: `${CLOUD_ROOT}/${folder}`,
      });
      return { url: res.secure_url, public_id: res.public_id, provider: "cloudinary", duration: res.duration };
    } finally {
      await fs.unlink(file.path).catch(() => {});
    }
  }

  return {
    url: `/uploads/${folder}/${path.basename(file.path)}`,
    public_id: `${folder}/${path.basename(file.path)}`,
    provider: "local",
  };
}

export async function removeFile(asset, resourceType = "image") {
  if (!asset?.public_id) return;
  try {
    if (asset.provider === "cloudinary") {
      await cloudinary.uploader.destroy(asset.public_id, { resource_type: resourceType });
    } else if (asset.provider === "local") {
      const target = path.resolve(config.uploadsDir, asset.public_id);
      if (target.startsWith(config.uploadsDir + path.sep)) await fs.unlink(target);
    }
  } catch (err) {
    console.warn("Could not remove file", asset.public_id, err.message);
  }
}

// Remove any files multer saved for a request that ended up failing
export async function discardUploads(req) {
  const files = [req.file, ...Object.values(req.files || {}).flat()].filter(Boolean);
  await Promise.all(files.map((f) => fs.unlink(f.path).catch(() => {})));
}

/**
 * Direct browser → Cloudinary uploads. Serverless hosts (Vercel) cap request bodies at ~4.5 MB,
 * so big videos can't pass through the API. The browser gets a short-lived signature, uploads
 * straight to Cloudinary, then tells the API the public_id.
 */
export function signDirectUpload(folder) {
  const timestamp = Math.round(Date.now() / 1000);
  const params = { folder: `${CLOUD_ROOT}/${folder}`, timestamp };
  return {
    cloudName: config.cloudinary.cloud_name,
    apiKey: config.cloudinary.api_key,
    ...params,
    signature: cloudinary.utils.api_sign_request(params, config.cloudinary.api_secret),
  };
}

/** Look up an asset the browser uploaded directly, so the URL/duration come from Cloudinary, not the client. */
export async function fetchDirectUpload(publicId, resourceType) {
  const folder = `${CLOUD_ROOT}/${resourceType === "video" ? "videos" : "images"}/`;
  if (typeof publicId !== "string" || !publicId.startsWith(folder)) throw new ApiError(400, `Invalid ${resourceType} upload`);
  try {
    const r = await cloudinary.api.resource(publicId, { resource_type: resourceType });
    return { url: r.secure_url, public_id: r.public_id, provider: "cloudinary", duration: r.duration };
  } catch {
    throw new ApiError(400, `The ${resourceType} upload wasn't found on Cloudinary`);
  }
}
