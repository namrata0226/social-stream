import mongoose, { Schema } from "mongoose";

export { User } from "./user.model.js";
export { Video } from "./video.model.js";

const ref = (model, opts = {}) => ({ type: Schema.Types.ObjectId, ref: model, ...opts });

// Comments support one level of replies via `parent`
const commentSchema = new Schema(
  {
    content: { type: String, required: true, trim: true, maxlength: 2000 },
    video: ref("Video", { required: true, index: true }),
    owner: ref("User", { required: true }),
    parent: ref("Comment", { default: null, index: true }),
    edited: { type: Boolean, default: false },
  },
  { timestamps: true }
);
export const Comment = mongoose.model("Comment", commentSchema);

// A reaction on exactly one of video / comment / post. Videos support like + dislike.
const likeSchema = new Schema(
  {
    likedBy: ref("User", { required: true }),
    video: ref("Video"),
    comment: ref("Comment"),
    post: ref("Post"),
    type: { type: String, enum: ["like", "dislike"], default: "like" },
  },
  { timestamps: true }
);
likeSchema.index({ likedBy: 1, video: 1 }, { unique: true, partialFilterExpression: { video: { $exists: true } } });
likeSchema.index({ likedBy: 1, comment: 1 }, { unique: true, partialFilterExpression: { comment: { $exists: true } } });
likeSchema.index({ likedBy: 1, post: 1 }, { unique: true, partialFilterExpression: { post: { $exists: true } } });
export const Like = mongoose.model("Like", likeSchema);

const subscriptionSchema = new Schema(
  {
    subscriber: ref("User", { required: true }),
    channel: ref("User", { required: true, index: true }),
  },
  { timestamps: true }
);
subscriptionSchema.index({ subscriber: 1, channel: 1 }, { unique: true });
export const Subscription = mongoose.model("Subscription", subscriptionSchema);

// Community posts (formerly "tweets")
const postSchema = new Schema(
  {
    content: { type: String, required: true, trim: true, maxlength: 2000 },
    owner: ref("User", { required: true, index: true }),
  },
  { timestamps: true }
);
export const Post = mongoose.model("Post", postSchema);

const playlistSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 100 },
    description: { type: String, default: "", maxlength: 1000 },
    videos: [ref("Video")],
    owner: ref("User", { required: true, index: true }),
    isPublic: { type: Boolean, default: true },
  },
  { timestamps: true }
);
export const Playlist = mongoose.model("Playlist", playlistSchema);

// Per-user watch progress: powers History, "Continue Watching" and resume playback
const watchSchema = new Schema(
  {
    user: ref("User", { required: true }),
    video: ref("Video", { required: true }),
    position: { type: Number, default: 0 },
    duration: { type: Number, default: 0 },
    completed: { type: Boolean, default: false },
    lastViewCountedAt: Date,
  },
  { timestamps: true }
);
watchSchema.index({ user: 1, video: 1 }, { unique: true });
watchSchema.index({ user: 1, updatedAt: -1 });
export const WatchHistory = mongoose.model("WatchHistory", watchSchema);

// "Moments": timestamped emoji reactions that replay on the timeline for every viewer
export const MOMENT_EMOJIS = ["🔥", "😂", "😮", "❤️", "👏", "🤯"];
const momentSchema = new Schema(
  {
    video: ref("Video", { required: true }),
    user: ref("User", { required: true }),
    emoji: { type: String, enum: MOMENT_EMOJIS, required: true },
    time: { type: Number, required: true, min: 0 },
  },
  { timestamps: true }
);
momentSchema.index({ video: 1, time: 1 });
momentSchema.index({ user: 1, video: 1, createdAt: -1 });
export const Moment = mongoose.model("Moment", momentSchema);

// Private timestamped notes a viewer keeps on a video
const noteSchema = new Schema(
  {
    user: ref("User", { required: true }),
    video: ref("Video", { required: true }),
    time: { type: Number, required: true, min: 0 },
    text: { type: String, required: true, trim: true, maxlength: 1000 },
  },
  { timestamps: true }
);
noteSchema.index({ user: 1, video: 1, time: 1 });
noteSchema.index({ user: 1, updatedAt: -1 });
export const Note = mongoose.model("Note", noteSchema);
