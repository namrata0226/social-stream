import { Playlist, Video } from "../models/index.js";
import { ApiError } from "../utils/ApiError.js";
import { ok } from "../utils/ApiResponse.js";
import { ownerLookup, toId, videoCardProject } from "../utils/helpers.js";

const summary = [
  {
    $lookup: {
      from: "videos",
      localField: "videos",
      foreignField: "_id",
      as: "vids",
      pipeline: [{ $match: { isPublished: true } }, { $project: { thumbnail: 1 } }],
    },
  },
  {
    $addFields: {
      videosCount: { $size: "$vids" },
      thumbnail: { $arrayElemAt: ["$vids.thumbnail", 0] },
    },
  },
  { $project: { vids: 0 } },
];

// GET /playlists/user/:userId (?videoId= marks which playlists already contain that video)
export const getUserPlaylists = async (req, res) => {
  const owner = toId(req.params.userId, "userId");
  const isOwner = req.user?._id.equals(owner);
  const match = isOwner ? { owner } : { owner, isPublic: true };
  const videoId = req.query.videoId ? toId(req.query.videoId, "videoId") : null;
  const docs = await Playlist.aggregate([
    { $match: match },
    { $sort: { updatedAt: -1 } },
    ...(videoId ? [{ $addFields: { hasVideo: { $in: [videoId, "$videos"] } } }] : []),
    ...summary,
  ]);
  return ok(res, docs);
};

export const getPlaylist = async (req, res) => {
  const id = toId(req.params.playlistId, "playlistId");
  const playlist = await Playlist.findById(id).lean();
  if (!playlist) throw new ApiError(404, "Playlist not found");
  const isOwner = req.user?._id.equals(playlist.owner);
  if (!playlist.isPublic && !isOwner) throw new ApiError(404, "Playlist not found");

  const videos = await Video.aggregate([
    { $match: { _id: { $in: playlist.videos }, ...(isOwner ? {} : { isPublished: true }) } },
    ...ownerLookup(),
    { $project: videoCardProject },
  ]);
  const order = new Map(playlist.videos.map((v, i) => [String(v), i]));
  videos.sort((a, b) => order.get(String(a._id)) - order.get(String(b._id)));
  const [withOwner] = await Playlist.aggregate([{ $match: { _id: id } }, ...ownerLookup(), { $project: { owner: 1 } }]);

  return ok(res, {
    ...playlist,
    owner: withOwner.owner,
    videos,
    totalViews: videos.reduce((s, v) => s + (v.views || 0), 0),
    totalDuration: videos.reduce((s, v) => s + (v.duration || 0), 0),
    isOwner,
  });
};

export const createPlaylist = async (req, res) => {
  const { name, description = "", isPublic = true, videoId } = req.body;
  if (!name?.trim()) throw new ApiError(400, "Playlist name is required");
  const playlist = await Playlist.create({
    name: name.trim(),
    description,
    isPublic: String(isPublic) !== "false",
    owner: req.user._id,
    videos: videoId ? [toId(videoId, "videoId")] : [],
  });
  return ok(res, playlist, "Playlist created", 201);
};

const ownPlaylist = async (req) => {
  const playlist = await Playlist.findById(toId(req.params.playlistId, "playlistId"));
  if (!playlist) throw new ApiError(404, "Playlist not found");
  if (!playlist.owner.equals(req.user._id)) throw new ApiError(403, "You can only modify your own playlists");
  return playlist;
};

export const updatePlaylist = async (req, res) => {
  const playlist = await ownPlaylist(req);
  const { name, description, isPublic } = req.body;
  if (name !== undefined) {
    if (!name.trim()) throw new ApiError(400, "Playlist name is required");
    playlist.name = name.trim();
  }
  if (description !== undefined) playlist.description = description;
  if (isPublic !== undefined) playlist.isPublic = String(isPublic) !== "false";
  await playlist.save();
  return ok(res, playlist, "Playlist updated");
};

export const deletePlaylist = async (req, res) => {
  const playlist = await ownPlaylist(req);
  await playlist.deleteOne();
  return ok(res, {}, "Playlist deleted");
};

// POST /playlists/:playlistId/videos/:videoId — toggles membership
export const toggleVideoInPlaylist = async (req, res) => {
  const playlist = await ownPlaylist(req);
  const videoId = toId(req.params.videoId, "videoId");
  if (!(await Video.exists({ _id: videoId }))) throw new ApiError(404, "Video not found");
  const has = playlist.videos.some((v) => v.equals(videoId));
  if (has) playlist.videos.pull(videoId);
  else playlist.videos.push(videoId);
  await playlist.save();
  return ok(res, { hasVideo: !has }, has ? `Removed from ${playlist.name}` : `Saved to ${playlist.name}`);
};
