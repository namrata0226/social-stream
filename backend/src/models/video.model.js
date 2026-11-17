import mongoose, { Schema } from "mongoose";
import { assetSchema } from "./user.model.js";
import { CATEGORIES } from "../utils/helpers.js";

const videoSchema = new Schema(
  {
    videoFile: { type: assetSchema, required: true },
    thumbnail: { type: assetSchema, required: true },
    owner: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    title: { type: String, required: true, trim: true, maxlength: 120 },
    description: { type: String, default: "", maxlength: 5000 },
    category: { type: String, enum: CATEGORIES, default: "Other", index: true },
    tags: [{ type: String, lowercase: true, trim: true }],
    duration: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    isPublished: { type: Boolean, default: true },
    isFeatured: { type: Boolean, default: false },
  },
  { timestamps: true }
);

videoSchema.index({ title: "text", description: "text", tags: "text" }, { weights: { title: 5, tags: 3, description: 1 } });
videoSchema.index({ isPublished: 1, createdAt: -1 });

export const Video = mongoose.model("Video", videoSchema);
