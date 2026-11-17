import { Video, User, Like, Comment, Subscription, WatchHistory, Playlist } from "../models/index.js";
import { ApiError } from "../utils/ApiError.js";
import { ok } from "../utils/ApiResponse.js";
import { persistFile, removeFile, discardUploads, fetchDirectUpload } from "../utils/storage.js";
import { useCloudinary } from "../config.js";
import {
  CATEGORIES,
  escapeRegex,
  ownerLookup,
  pageResult,
  paging,
  toId,
  videoCardProject,
} from "../utils/helpers.js";

const VIEW_COOLDOWN_MS = 6 * 60 * 60 * 1000; // one counted view per user per 6h
const SORTS = {
  latest: { createdAt: -1 },
  oldest: { createdAt: 1 },
  popular: { views: -1, createdAt: -1 },
  duration: { duration: -1 },
};

const trendingScore = {
  $divide: [
    { $add: ["$views", 1] },
    { $pow: [{ $add: [{ $divide: [{ $subtract: ["$$NOW", "$createdAt"] }, 3600000] }, 2] }, 1.3] },
  ],
};

const cards = (match, sort, limit, skip = 0) => [
  { $match: match },
  { $sort: sort },
  ...(skip ? [{ $skip: skip }] : []),
  { $limit: limit },
  ...ownerLookup(),
  { $project: videoCardProject },
];

const parseTags = (tags) => {
  if (!tags) return [];
  const list = Array.isArray(tags) ? tags : String(tags).split(",");
  return [...new Set(list.map((t) => t.trim().toLowerCase().replace(/^#/, "")).filter(Boolean))].slice(0, 15);
};

// GET /videos?q=&category=&owner=&sort=latest|popular|oldest|duration&page=&limit=
export const getAllVideos = async (req, res) => {
  const { page, limit, skip } = paging(req.query, 12);
  const { q, category, owner, sort = "latest" } = req.query;
  const match = { isPublished: true };

  if (owner) {
    match.owner = toId(owner, "owner");
    // owners can see their own drafts on their channel
    if (req.user?._id.equals(match.owner) && req.query.includeDrafts === "true") delete match.isPublished;
  }
  if (category && category !== "All") {
    // a comma-separated list powers the mood picker ("Chill" = Music, Travel, Lifestyle)
    const cats = String(category).split(",").map((c) => c.trim()).filter((c) => CATEGORIES.includes(c));
    match.category = cats.length > 1 ? { $in: cats } : cats[0] ?? category;
  }

  let sortStage = SORTS[sort] || SORTS.latest;
  if (q?.trim()) {
    const rx = new RegExp(escapeRegex(q.trim()), "i");
    const owners = await User.find({ $or: [{ username: rx }, { fullName: rx }] }).select("_id").limit(50);
    match.$or = [{ title: rx }, { description: rx }, { tags: rx }, { owner: { $in: owners.map((o) => o._id) } }];
    if (sort === "latest" && !req.query.sort) sortStage = { views: -1, createdAt: -1 };
  }

  const [docs, total] = await Promise.all([
    Video.aggregate(cards(match, sortStage, limit, skip)),
    Video.countDocuments(match),
  ]);
  return ok(res, pageResult(docs, total, page, limit));
};

// GET /videos/browse — home page: spotlight items + themed rows
export const browse = async (req, res) => {
  const pub = { isPublished: true };

  const [featured, trending, latest, popular, categoryCounts] = await Promise.all([
    Video.aggregate([
      { $match: pub },
      { $addFields: { score: { $add: [{ $cond: ["$isFeatured", 1e9, 0] }, trendingScore] } } },
      ...cards({}, { score: -1 }, 5),
    ]),
    Video.aggregate([{ $match: pub }, { $addFields: { score: trendingScore } }, ...cards({}, { score: -1 }, 15)]),
    Video.aggregate(cards(pub, { createdAt: -1 }, 15)),
    Video.aggregate(cards(pub, { views: -1 }, 15)),
    Video.aggregate([{ $match: pub }, { $group: { _id: "$category", n: { $sum: 1 } } }, { $sort: { n: -1 } }]),
  ]);

  const rows = [
    { key: "trending", title: "Rising Right Now", videos: trending },
    { key: "new", title: "Fresh Drops", videos: latest },
    { key: "popular", title: "Crowd Favorites", videos: popular },
  ];

  if (req.user) {
    const [continueWatching, subs, myList] = await Promise.all([
      WatchHistory.aggregate([
        { $match: { user: req.user._id, completed: false, position: { $gt: 5 } } },
        { $sort: { updatedAt: -1 } },
        { $limit: 15 },
        {
          $lookup: {
            from: "videos",
            localField: "video",
            foreignField: "_id",
            as: "video",
            pipeline: [{ $match: pub }, ...ownerLookup(), { $project: videoCardProject }],
          },
        },
        { $unwind: "$video" },
        {
          $replaceRoot: {
            newRoot: { $mergeObjects: ["$video", { progress: { position: "$position", duration: "$duration" } }] },
          },
        },
      ]),
      Subscription.find({ subscriber: req.user._id }).select("channel"),
      Video.aggregate(cards({ _id: { $in: req.user.myList }, ...pub }, { createdAt: -1 }, 15)),
    ]);
    const subVideos = subs.length
      ? await Video.aggregate(cards({ ...pub, owner: { $in: subs.map((s) => s.channel) } }, { createdAt: -1 }, 15))
      : [];
    if (subVideos.length) rows.unshift({ key: "subscriptions", title: "New From People You Follow", videos: subVideos });
    if (myList.length) rows.unshift({ key: "mylist", title: "Your Watchlist", videos: myList });
    if (continueWatching.length)
      rows.unshift({ key: "continue", title: `Pick up where you left off, ${req.user.fullName.split(" ")[0]}`, videos: continueWatching });
  }

  const categoryRows = await Promise.all(
    categoryCounts.slice(0, 8).map(async ({ _id }) => ({
      key: `cat-${_id}`,
      title: _id,
      category: _id,
      videos: await Video.aggregate(cards({ ...pub, category: _id }, { views: -1, createdAt: -1 }, 15)),
    }))
  );

  return ok(res, {
    featured,
    rows: [...rows, ...categoryRows].filter((r) => r.videos.length),
    categories: CATEGORIES,
  });
};

export const getCategories = async (_req, res) => ok(res, CATEGORIES);

// POST /videos
//  multipart: videoFile, thumbnail + fields (title, description, category, tags, duration, isPublished)
//  or JSON after a direct Cloudinary upload: videoPublicId, thumbnailPublicId + the same fields
export const publishVideo = async (req, res) => {
  try {
    const { title, description = "", category = "Other", tags, duration, isPublished, videoPublicId, thumbnailPublicId } = req.body;
    if (!title?.trim()) throw new ApiError(400, "Title is required");
    if (!CATEGORIES.includes(category)) throw new ApiError(400, "Invalid category");

    let videoAsset, thumbAsset;
    if (videoPublicId) {
      if (!useCloudinary) throw new ApiError(400, "Direct uploads need Cloudinary to be configured");
      if (!thumbnailPublicId) throw new ApiError(400, "Thumbnail is required");
      [videoAsset, thumbAsset] = await Promise.all([
        fetchDirectUpload(videoPublicId, "video"),
        fetchDirectUpload(thumbnailPublicId, "image"),
      ]);
    } else {
      const videoFile = req.files?.videoFile?.[0];
      const thumb = req.files?.thumbnail?.[0];
      if (!videoFile) throw new ApiError(400, "Video file is required");
      if (!thumb) throw new ApiError(400, "Thumbnail is required");
      [videoAsset, thumbAsset] = await Promise.all([persistFile(videoFile), persistFile(thumb)]);
    }
    const video = await Video.create({
      title: title.trim(),
      description,
      category,
      tags: parseTags(tags),
      duration: Number(videoAsset.duration ?? duration) || 0,
      videoFile: videoAsset,
      thumbnail: thumbAsset,
      owner: req.user._id,
      isPublished: isPublished === undefined ? true : String(isPublished) === "true",
    });
    return ok(res, video, "Video uploaded", 201);
  } catch (err) {
    await discardUploads(req);
    throw err;
  }
};

// GET /videos/:videoId — full details for the watch page
export const getVideoById = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const [video] = await Video.aggregate([{ $match: { _id: videoId } }, ...ownerLookup()]);
  if (!video) throw new ApiError(404, "Video not found");
  const userId = req.user?._id;
  const isOwner = Boolean(userId && video.owner?._id.equals(userId));
  if (!video.isPublished && !isOwner) throw new ApiError(404, "This video is private");

  const [likes, dislikes, myReaction, subscribersCount, isSubscribed, progress, commentsCount] = await Promise.all([
    Like.countDocuments({ video: videoId, type: "like" }),
    Like.countDocuments({ video: videoId, type: "dislike" }),
    userId ? Like.findOne({ video: videoId, likedBy: userId }).select("type") : null,
    Subscription.countDocuments({ channel: video.owner?._id }),
    userId ? Subscription.exists({ channel: video.owner?._id, subscriber: userId }) : null,
    userId ? WatchHistory.findOne({ user: userId, video: videoId }).select("position duration completed") : null,
    Comment.countDocuments({ video: videoId }),
  ]);

  return ok(res, {
    ...video,
    likesCount: likes,
    dislikesCount: dislikes,
    myReaction: myReaction?.type || null,
    commentsCount,
    owner: { ...video.owner, subscribersCount, isSubscribed: Boolean(isSubscribed) },
    inMyList: Boolean(req.user?.myList?.some((v) => v.equals(videoId))),
    progress: progress && !progress.completed ? progress.position : 0,
    isOwner,
  });
};

// POST /videos/:videoId/view — called by the player once playback starts
export const registerView = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  let count = true;
  if (req.user) {
    const now = new Date();
    const entry = await WatchHistory.findOneAndUpdate(
      { user: req.user._id, video: videoId },
      { $setOnInsert: { position: 0 } },
      { upsert: true, new: false }
    );
    count = !entry?.lastViewCountedAt || now - entry.lastViewCountedAt > VIEW_COOLDOWN_MS;
    await WatchHistory.updateOne(
      { user: req.user._id, video: videoId },
      { $set: { lastViewCountedAt: count ? now : entry.lastViewCountedAt } } // also bumps updatedAt
    );
  }
  const video = count
    ? await Video.findByIdAndUpdate(videoId, { $inc: { views: 1 } }, { new: true }).select("views")
    : await Video.findById(videoId).select("views");
  if (!video) throw new ApiError(404, "Video not found");
  return ok(res, { views: video.views, counted: count });
};

// POST /videos/:videoId/progress { position, duration }
export const saveProgress = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const position = Math.max(0, Number(req.body.position) || 0);
  const duration = Math.max(0, Number(req.body.duration) || 0);
  const completed = duration > 0 && position / duration >= 0.95;
  await WatchHistory.updateOne(
    { user: req.user._id, video: videoId },
    { $set: { position: completed ? 0 : position, duration, completed } },
    { upsert: true }
  );
  return ok(res, { position, completed });
};

// GET /videos/:videoId/related — "Up next"
export const getRelated = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const video = await Video.findById(videoId).select("category tags owner");
  if (!video) throw new ApiError(404, "Video not found");
  const limit = Math.min(30, Number(req.query.limit) || 15);

  const related = await Video.aggregate([
    { $match: { _id: { $ne: videoId }, isPublished: true } },
    {
      $addFields: {
        relevance: {
          $add: [
            { $cond: [{ $eq: ["$category", video.category] }, 3, 0] },
            { $cond: [{ $eq: ["$owner", video.owner] }, 2, 0] },
            { $size: { $setIntersection: ["$tags", video.tags || []] } },
          ],
        },
      },
    },
    { $sort: { relevance: -1, views: -1, createdAt: -1 } },
    { $limit: limit },
    ...ownerLookup(),
    { $project: videoCardProject },
  ]);
  return ok(res, related);
};

const findOwned = async (req) => {
  const video = await Video.findById(toId(req.params.videoId, "videoId"));
  if (!video) throw new ApiError(404, "Video not found");
  if (!video.owner.equals(req.user._id)) throw new ApiError(403, "You can only modify your own videos");
  return video;
};

// PATCH /videos/:videoId (multipart optional thumbnail)
export const updateVideo = async (req, res) => {
  try {
    const video = await findOwned(req);
    const { title, description, category, tags, isPublished } = req.body;
    if (title !== undefined) {
      if (!title.trim()) throw new ApiError(400, "Title cannot be empty");
      video.title = title.trim();
    }
    if (description !== undefined) video.description = description;
    if (category !== undefined) {
      if (!CATEGORIES.includes(category)) throw new ApiError(400, "Invalid category");
      video.category = category;
    }
    if (tags !== undefined) video.tags = parseTags(tags);
    if (isPublished !== undefined) video.isPublished = String(isPublished) === "true";
    if (req.file) {
      const old = video.thumbnail;
      video.thumbnail = await persistFile(req.file);
      await removeFile(old, "image");
    }
    await video.save();
    return ok(res, video, "Video updated");
  } catch (err) {
    await discardUploads(req);
    throw err;
  }
};

export const togglePublish = async (req, res) => {
  const video = await findOwned(req);
  video.isPublished = !video.isPublished;
  await video.save();
  return ok(res, { isPublished: video.isPublished }, video.isPublished ? "Video published" : "Video unpublished");
};

export const deleteVideo = async (req, res) => {
  const video = await findOwned(req);
  const comments = await Comment.find({ video: video._id }).select("_id");
  await Promise.all([
    Video.deleteOne({ _id: video._id }),
    Like.deleteMany({ $or: [{ video: video._id }, { comment: { $in: comments.map((c) => c._id) } }] }),
    Comment.deleteMany({ video: video._id }),
    WatchHistory.deleteMany({ video: video._id }),
    Playlist.updateMany({}, { $pull: { videos: video._id } }),
    User.updateMany({}, { $pull: { myList: video._id } }),
  ]);
  await Promise.all([removeFile(video.videoFile, "video"), removeFile(video.thumbnail, "image")]);
  return ok(res, {}, "Video deleted");
};
