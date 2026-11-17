import jwt from "jsonwebtoken";
import { config } from "../config.js";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";

async function resolveUser(req) {
  const token = req.cookies?.accessToken || req.header("Authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, config.accessSecret);
    return await User.findById(decoded._id).select("-password -refreshToken");
  } catch {
    return null;
  }
}

export const verifyJWT = async (req, _res, next) => {
  const user = await resolveUser(req);
  if (!user) throw new ApiError(401, "Please sign in to continue");
  req.user = user;
  next();
};

// Attaches req.user when a valid token is present, but never blocks the request
export const optionalAuth = async (req, _res, next) => {
  req.user = await resolveUser(req);
  next();
};
