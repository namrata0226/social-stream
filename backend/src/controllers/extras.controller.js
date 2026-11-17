// Features unique to Kinora: Moments (timeline reactions), private Notes, and Shuffle.
import { Moment, MOMENT_EMOJIS, Note, Video } from "../models/index.js";
import { ApiError } from "../utils/ApiError.js";
import { ok } from "../utils/ApiResponse.js";
import { CATEGORIES, ownerLookup, toId, videoCardProject } from "../utils/helpers.js";

const MAX_MOMENTS_PER_USER_VIDEO = 300;

// Visible videos only: published, or the viewer's own draft
async function findVisibleVideo(videoId, user) {
  const video = await Video.findById(videoId).select("owner isPublished duration");
  if (!video || (!video.isPublished && !user?._id.equals(video.owner))) throw new ApiError(404, "Video not found");
  return video;
}

// ---------------- Moments ----------------

// GET /moments/video/:videoId → { emojis, buckets: [{ t, e, n }], counts, total }
// Reactions are grouped per whole second and emoji so the payload stays small on busy videos.
export const getMoments = async (req, res) => {
  const video = toId(req.params.videoId, "videoId");
  const buckets = await Moment.aggregate([
    { $match: { video } },
    { $group: { _id: { t: { $floor: "$time" }, e: "$emoji" }, n: { $sum: 1 } } },
    { $project: { _id: 0, t: "$_id.t", e: "$_id.e", n: 1 } },
    { $sort: { t: 1 } },
    { $limit: 5000 },
  ]);
  const counts = Object.fromEntries(MOMENT_EMOJIS.map((e) => [e, 0]));
  let total = 0;
  for (const b of buckets) {
    counts[b.e] = (counts[b.e] || 0) + b.n;
    total += b.n;
  }
  return ok(res, { emojis: MOMENT_EMOJIS, buckets, counts, total });
};

// POST /moments/video/:videoId { emoji, time }
export const addMoment = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const { emoji } = req.body;
  const time = Number(req.body.time);
  if (!MOMENT_EMOJIS.includes(emoji)) throw new ApiError(400, "Unsupported reaction");
  if (!Number.isFinite(time) || time < 0) throw new ApiError(400, "Invalid time");

  const video = await findVisibleVideo(videoId, req.user);
  if (video.duration && time > video.duration + 1) throw new ApiError(400, "Time is past the end of the video");

  const [recent, mine] = await Promise.all([
    Moment.exists({ user: req.user._id, video: videoId, createdAt: { $gt: new Date(Date.now() - 400) } }),
    Moment.countDocuments({ user: req.user._id, video: videoId }),
  ]);
  if (recent) throw new ApiError(429, "Slow down a little");
  if (mine >= MAX_MOMENTS_PER_USER_VIDEO) throw new ApiError(429, "You've reacted a lot on this video already");

  const m = await Moment.create({ video: videoId, user: req.user._id, emoji, time });
  return ok(res, { t: Math.floor(m.time), e: m.emoji, n: 1 }, "Moment added", 201);
};

// ---------------- Notes ----------------

// GET /notes/video/:videoId — the signed-in user's notes on one video
export const getVideoNotes = async (req, res) => {
  const video = toId(req.params.videoId, "videoId");
  const notes = await Note.find({ user: req.user._id, video }).sort({ time: 1 }).select("time text createdAt updatedAt");
  return ok(res, notes);
};

// POST /notes/video/:videoId { time, text }
export const addNote = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const text = String(req.body.text || "").trim();
  const time = Math.max(0, Number(req.body.time) || 0);
  if (!text) throw new ApiError(400, "Write something first");
  await findVisibleVideo(videoId, req.user);
  const note = await Note.create({ user: req.user._id, video: videoId, time, text });
  return ok(res, note, "Note saved", 201);
};

// PATCH /notes/:noteId { text }
export const updateNote = async (req, res) => {
  const text = String(req.body.text || "").trim();
  if (!text) throw new ApiError(400, "Note can't be empty");
  const note = await Note.findOneAndUpdate(
    { _id: toId(req.params.noteId, "noteId"), user: req.user._id },
    { $set: { text } },
    { new: true, runValidators: true }
  );
  if (!note) throw new ApiError(404, "Note not found");
  return ok(res, note, "Note updated");
};

// DELETE /notes/:noteId
export const deleteNote = async (req, res) => {
  const r = await Note.deleteOne({ _id: toId(req.params.noteId, "noteId"), user: req.user._id });
  if (!r.deletedCount) throw new ApiError(404, "Note not found");
  return ok(res, {}, "Note deleted");
};

// GET /notes — every note the user has written, grouped by video, most recently edited first
export const getAllNotes = async (req, res) => {
  const groups = await Note.aggregate([
    { $match: { user: req.user._id } },
    { $sort: { time: 1 } },
    {
      $group: {
        _id: "$video",
        notes: { $push: { _id: "$_id", time: "$time", text: "$text", updatedAt: "$updatedAt" } },
        lastEdited: { $max: "$updatedAt" },
      },
    },
    { $sort: { lastEdited: -1 } },
    { $limit: 200 },
    {
      $lookup: {
        from: "videos",
        localField: "_id",
        foreignField: "_id",
        as: "video",
        pipeline: [...ownerLookup(), { $project: videoCardProject }],
      },
    },
    { $unwind: "$video" },
    { $project: { _id: 0, video: 1, notes: 1, lastEdited: 1 } },
  ]);
  return ok(res, groups);
};

// ---------------- Shuffle ----------------

// GET /videos/shuffle?categories=Music,Travel — one random published video
export const shuffle = async (req, res) => {
  const match = { isPublished: true };
  const cats = String(req.query.categories || "")
    .split(",")
    .map((c) => c.trim())
    .filter((c) => CATEGORIES.includes(c));
  if (cats.length) match.category = { $in: cats };
  if (req.query.exclude) match._id = { $ne: toId(req.query.exclude, "exclude") };
  const [video] = await Video.aggregate([{ $match: match }, { $sample: { size: 1 } }, { $project: { _id: 1, title: 1 } }]);
  if (!video) throw new ApiError(404, "No videos to shuffle yet");
  return ok(res, video);
};
