import mongoose from "mongoose";
import { ApiError } from "./ApiError.js";

export const toId = (id, name = "id") => {
  if (!mongoose.isValidObjectId(id)) throw new ApiError(400, `Invalid ${name}`);
  return new mongoose.Types.ObjectId(String(id));
};

export const paging = (query, defLimit = 12, maxLimit = 50) => {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(maxLimit, Math.max(1, parseInt(query.limit, 10) || defLimit));
  return { page, limit, skip: (page - 1) * limit };
};

export const pageResult = (docs, total, page, limit) => ({
  docs,
  total,
  page,
  limit,
  totalPages: Math.ceil(total / limit),
  hasNextPage: page * limit < total,
});

export const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// $lookup stages that attach a small public profile of the owner
export const ownerLookup = (localField = "owner", as = "owner") => [
  {
    $lookup: {
      from: "users",
      localField,
      foreignField: "_id",
      as,
      pipeline: [{ $project: { username: 1, fullName: 1, avatar: 1 } }],
    },
  },
  { $unwind: { path: `$${as}`, preserveNullAndEmptyArrays: true } },
];

// Fields needed to render a video card/tile
export const videoCardProject = {
  title: 1,
  thumbnail: 1,
  videoFile: 1, // used for hover previews
  duration: 1,
  views: 1,
  category: 1,
  createdAt: 1,
  isPublished: 1,
  description: { $substrCP: ["$description", 0, 300] },
  owner: 1,
};

export const CATEGORIES = [
  "Movies",
  "Music",
  "Gaming",
  "Education",
  "Technology",
  "Comedy",
  "Sports",
  "News",
  "Travel",
  "Food",
  "Lifestyle",
  "Other",
];
