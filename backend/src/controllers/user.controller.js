import jwt from "jsonwebtoken";
import { config } from "../config.js";
import { User, Video, Subscription, WatchHistory } from "../models/index.js";
import { ApiError } from "../utils/ApiError.js";
import { ok } from "../utils/ApiResponse.js";
import { persistFile, removeFile, discardUploads } from "../utils/storage.js";
import { ownerLookup, paging, pageResult, toId, videoCardProject } from "../utils/helpers.js";

const cookieOptions = (maxAgeMs) => ({
  httpOnly: true,
  secure: config.isProd,
  sameSite: config.isProd ? "none" : "lax",
  maxAge: maxAgeMs,
});
const DAY = 24 * 60 * 60 * 1000;

async function issueTokens(res, user) {
  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();
  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });
  res.cookie("accessToken", accessToken, cookieOptions(DAY));
  res.cookie("refreshToken", refreshToken, cookieOptions(10 * DAY));
  return { accessToken, refreshToken };
}

export const registerUser = async (req, res) => {
  try {
    const { fullName, email, username, password } = req.body;
    if ([fullName, email, username, password].some((f) => !f?.toString().trim())) {
      throw new ApiError(400, "Full name, email, username and password are required");
    }
    if (password.length < 6) throw new ApiError(400, "Password must be at least 6 characters");

    const exists = await User.findOne({ $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }] });
    if (exists) throw new ApiError(409, "A user with that email or username already exists");

    const avatar = await persistFile(req.files?.avatar?.[0]);
    const coverImage = await persistFile(req.files?.coverImage?.[0]);

    const user = await User.create({ fullName, email, username, password, avatar, coverImage });
    const tokens = await issueTokens(res, user);
    return ok(res, { user: user.toPublic(), ...tokens }, "Account created", 201);
  } catch (err) {
    await discardUploads(req);
    throw err;
  }
};

export const loginUser = async (req, res) => {
  const { identifier, email, username, password } = req.body;
  const id = (identifier || email || username || "").toLowerCase().trim();
  if (!id || !password) throw new ApiError(400, "Email/username and password are required");

  const user = await User.findOne({ $or: [{ email: id }, { username: id }] });
  if (!user || !(await user.isPasswordCorrect(password))) throw new ApiError(401, "Invalid credentials");

  const tokens = await issueTokens(res, user);
  return ok(res, { user: user.toPublic(), ...tokens }, "Logged in");
};

export const logoutUser = async (req, res) => {
  await User.findByIdAndUpdate(req.user._id, { $unset: { refreshToken: 1 } });
  res.clearCookie("accessToken", cookieOptions(0));
  res.clearCookie("refreshToken", cookieOptions(0));
  return ok(res, {}, "Logged out");
};

export const refreshAccessToken = async (req, res) => {
  const incoming = req.cookies?.refreshToken || req.body?.refreshToken;
  if (!incoming) throw new ApiError(401, "Refresh token missing");
  let decoded;
  try {
    decoded = jwt.verify(incoming, config.refreshSecret);
  } catch {
    throw new ApiError(401, "Refresh token expired, please sign in again");
  }
  const user = await User.findById(decoded._id);
  if (!user || user.refreshToken !== incoming) throw new ApiError(401, "Refresh token is invalid");
  const tokens = await issueTokens(res, user);
  return ok(res, tokens, "Token refreshed");
};

export const getCurrentUser = async (req, res) => ok(res, req.user);

// GET /users/session — like /me but never 401s: returns the user (renewing an expired
// access token from a valid refresh cookie) or null for guests.
export const getSession = async (req, res) => {
  if (req.user) return ok(res, req.user);
  const refresh = req.cookies?.refreshToken;
  if (refresh) {
    try {
      const { _id } = jwt.verify(refresh, config.refreshSecret);
      const user = await User.findById(_id);
      if (user && user.refreshToken === refresh) {
        await issueTokens(res, user);
        return ok(res, user.toPublic());
      }
    } catch {
      /* expired or invalid — treat as guest */
    }
  }
  return ok(res, null);
};

export const updateAccount = async (req, res) => {
  const { fullName, email, bio } = req.body;
  const update = {};
  if (fullName?.trim()) update.fullName = fullName.trim();
  if (bio !== undefined) update.bio = String(bio).slice(0, 1000);
  if (email?.trim()) {
    const taken = await User.findOne({ email: email.toLowerCase(), _id: { $ne: req.user._id } });
    if (taken) throw new ApiError(409, "Email is already in use");
    update.email = email;
  }
  const user = await User.findByIdAndUpdate(req.user._id, update, { new: true, runValidators: true }).select(
    "-password -refreshToken"
  );
  return ok(res, user, "Profile updated");
};

const replaceImage = (field) => async (req, res) => {
  if (!req.file) throw new ApiError(400, "Image file is required");
  const asset = await persistFile(req.file);
  const old = req.user[field];
  const user = await User.findByIdAndUpdate(req.user._id, { [field]: asset }, { new: true }).select(
    "-password -refreshToken"
  );
  await removeFile(old, "image");
  return ok(res, user, "Image updated");
};
export const updateAvatar = replaceImage("avatar");
export const updateCoverImage = replaceImage("coverImage");

export const changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) throw new ApiError(400, "New password must be at least 6 characters");
  const user = await User.findById(req.user._id);
  if (!(await user.isPasswordCorrect(oldPassword || ""))) throw new ApiError(400, "Current password is incorrect");
  user.password = newPassword;
  await user.save();
  return ok(res, {}, "Password changed");
};

export const getChannelProfile = async (req, res) => {
  const username = req.params.username?.toLowerCase();
  const channel = await User.findOne({ username }).select("username fullName bio avatar coverImage createdAt").lean();
  if (!channel) throw new ApiError(404, "Channel not found");

  const [subscribersCount, subscribedToCount, videosCount, viewsAgg, isSubscribed] = await Promise.all([
    Subscription.countDocuments({ channel: channel._id }),
    Subscription.countDocuments({ subscriber: channel._id }),
    Video.countDocuments({ owner: channel._id, isPublished: true }),
    Video.aggregate([{ $match: { owner: channel._id } }, { $group: { _id: null, views: { $sum: "$views" } } }]),
    req.user ? Subscription.exists({ channel: channel._id, subscriber: req.user._id }) : null,
  ]);

  return ok(res, {
    ...channel,
    subscribersCount,
    subscribedToCount,
    videosCount,
    totalViews: viewsAgg[0]?.views || 0,
    isSubscribed: Boolean(isSubscribed),
    isOwner: req.user?._id.equals(channel._id) || false,
  });
};

// ---------- History & Continue Watching ----------

const historyPipeline = (match, skip, limit) => [
  { $match: match },
  { $sort: { updatedAt: -1 } },
  { $skip: skip },
  { $limit: limit },
  {
    $lookup: {
      from: "videos",
      localField: "video",
      foreignField: "_id",
      as: "video",
      pipeline: [{ $match: { isPublished: true } }, ...ownerLookup(), { $project: videoCardProject }],
    },
  },
  { $unwind: "$video" },
  { $project: { _id: 0, watchedAt: "$updatedAt", position: 1, duration: 1, completed: 1, video: 1 } },
];

export const getWatchHistory = async (req, res) => {
  const { page, limit, skip } = paging(req.query, 20);
  const match = { user: req.user._id };
  const [docs, total] = await Promise.all([
    WatchHistory.aggregate(historyPipeline(match, skip, limit)),
    WatchHistory.countDocuments(match),
  ]);
  return ok(res, pageResult(docs, total, page, limit));
};

export const getContinueWatching = async (req, res) => {
  const match = { user: req.user._id, completed: false, position: { $gt: 5 } };
  const docs = await WatchHistory.aggregate(historyPipeline(match, 0, 20));
  return ok(res, docs);
};

export const removeFromHistory = async (req, res) => {
  await WatchHistory.deleteOne({ user: req.user._id, video: toId(req.params.videoId, "videoId") });
  return ok(res, {}, "Removed from history");
};

export const clearHistory = async (req, res) => {
  await WatchHistory.deleteMany({ user: req.user._id });
  return ok(res, {}, "Watch history cleared");
};

// ---------- Watchlist (stored as myList) ----------

export const getMyList = async (req, res) => {
  const ids = req.user.myList || [];
  const videos = await Video.aggregate([
    { $match: { _id: { $in: ids }, isPublished: true } },
    ...ownerLookup(),
    { $project: videoCardProject },
  ]);
  // keep the order the user added them in (most recent first)
  const order = new Map(ids.map((id, i) => [String(id), i]));
  videos.sort((a, b) => order.get(String(b._id)) - order.get(String(a._id)));
  return ok(res, videos);
};

export const toggleMyList = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  if (!(await Video.exists({ _id: videoId }))) throw new ApiError(404, "Video not found");
  const inList = req.user.myList.some((v) => v.equals(videoId));
  await User.updateOne({ _id: req.user._id }, inList ? { $pull: { myList: videoId } } : { $addToSet: { myList: videoId } });
  return ok(res, { inMyList: !inList }, inList ? "Removed from Watchlist" : "Added to Watchlist");
};
