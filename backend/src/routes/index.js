import { Router } from "express";
import mongoose from "mongoose";
import { verifyJWT, optionalAuth } from "../middlewares/auth.js";
import { upload } from "../middlewares/upload.js";
import * as users from "../controllers/user.controller.js";
import * as videos from "../controllers/video.controller.js";
import * as social from "../controllers/social.controller.js";
import * as playlists from "../controllers/playlist.controller.js";
import * as dashboard from "../controllers/dashboard.controller.js";
import * as extras from "../controllers/extras.controller.js";
import { ok } from "../utils/ApiResponse.js";
import { useCloudinary } from "../config.js";
import { signDirectUpload } from "../utils/storage.js";

const api = Router();

api.get("/healthcheck", (_req, res) =>
  ok(res, { status: "ok", db: mongoose.connection.readyState === 1 ? "connected" : "disconnected" })
);

// Signed params for direct browser → Cloudinary uploads (see utils/storage.js)
api.get("/uploads/direct", verifyJWT, (_req, res) =>
  ok(res, useCloudinary ? { enabled: true, video: signDirectUpload("videos"), image: signDirectUpload("images") } : { enabled: false })
);

// ---- users / auth ----
const u = Router();
u.post("/register", upload.fields([{ name: "avatar", maxCount: 1 }, { name: "coverImage", maxCount: 1 }]), users.registerUser);
u.post("/login", users.loginUser);
u.post("/logout", verifyJWT, users.logoutUser);
u.post("/refresh-token", users.refreshAccessToken);
u.get("/me", verifyJWT, users.getCurrentUser);
u.get("/session", optionalAuth, users.getSession);
u.patch("/me", verifyJWT, users.updateAccount);
u.patch("/me/avatar", verifyJWT, upload.single("avatar"), users.updateAvatar);
u.patch("/me/cover", verifyJWT, upload.single("coverImage"), users.updateCoverImage);
u.post("/me/password", verifyJWT, users.changePassword);
u.get("/c/:username", optionalAuth, users.getChannelProfile);
u.get("/history", verifyJWT, users.getWatchHistory);
u.delete("/history", verifyJWT, users.clearHistory);
u.delete("/history/:videoId", verifyJWT, users.removeFromHistory);
u.get("/continue-watching", verifyJWT, users.getContinueWatching);
u.get("/my-list", verifyJWT, users.getMyList);
u.post("/my-list/:videoId", verifyJWT, users.toggleMyList);
api.use("/users", u);

// ---- videos ----
const v = Router();
v.get("/", optionalAuth, videos.getAllVideos);
v.get("/browse", optionalAuth, videos.browse);
v.get("/categories", videos.getCategories);
v.get("/shuffle", extras.shuffle);
v.post("/", verifyJWT, upload.fields([{ name: "videoFile", maxCount: 1 }, { name: "thumbnail", maxCount: 1 }]), videos.publishVideo);
v.get("/:videoId", optionalAuth, videos.getVideoById);
v.patch("/:videoId", verifyJWT, upload.single("thumbnail"), videos.updateVideo);
v.delete("/:videoId", verifyJWT, videos.deleteVideo);
v.patch("/:videoId/publish", verifyJWT, videos.togglePublish);
v.post("/:videoId/view", optionalAuth, videos.registerView);
v.post("/:videoId/progress", verifyJWT, videos.saveProgress);
v.get("/:videoId/related", videos.getRelated);
api.use("/videos", v);

// ---- comments ----
const c = Router();
c.get("/video/:videoId", optionalAuth, social.getVideoComments);
c.post("/video/:videoId", verifyJWT, social.addComment);
c.get("/:commentId/replies", optionalAuth, social.getReplies);
c.patch("/:commentId", verifyJWT, social.updateComment);
c.delete("/:commentId", verifyJWT, social.deleteComment);
api.use("/comments", c);

// ---- likes ----
const l = Router();
l.post("/video/:videoId", verifyJWT, social.reactToVideo);
l.post("/comment/:id", verifyJWT, social.toggleCommentLike);
l.post("/post/:id", verifyJWT, social.togglePostLike);
l.get("/videos", verifyJWT, social.getLikedVideos);
api.use("/likes", l);

// ---- subscriptions ----
const s = Router();
s.post("/c/:channelId", verifyJWT, social.toggleSubscription);
s.get("/c/:channelId/subscribers", social.getChannelSubscribers);
s.get("/channels", verifyJWT, social.getSubscribedChannels);
s.get("/feed", verifyJWT, social.getSubscriptionFeed);
api.use("/subscriptions", s);

// ---- community posts ----
const p = Router();
p.get("/user/:userId", optionalAuth, social.getUserPosts);
p.post("/", verifyJWT, social.createPost);
p.patch("/:postId", verifyJWT, social.updatePost);
p.delete("/:postId", verifyJWT, social.deletePost);
api.use("/posts", p);

// ---- playlists ----
const pl = Router();
pl.get("/user/:userId", optionalAuth, playlists.getUserPlaylists);
pl.post("/", verifyJWT, playlists.createPlaylist);
pl.get("/:playlistId", optionalAuth, playlists.getPlaylist);
pl.patch("/:playlistId", verifyJWT, playlists.updatePlaylist);
pl.delete("/:playlistId", verifyJWT, playlists.deletePlaylist);
pl.post("/:playlistId/videos/:videoId", verifyJWT, playlists.toggleVideoInPlaylist);
api.use("/playlists", pl);

// ---- moments (timeline reactions) ----
const m = Router();
m.get("/video/:videoId", extras.getMoments);
m.post("/video/:videoId", verifyJWT, extras.addMoment);
api.use("/moments", m);

// ---- private notes ----
const n = Router();
n.use(verifyJWT);
n.get("/", extras.getAllNotes);
n.get("/video/:videoId", extras.getVideoNotes);
n.post("/video/:videoId", extras.addNote);
n.patch("/:noteId", extras.updateNote);
n.delete("/:noteId", extras.deleteNote);
api.use("/notes", n);

// ---- creator studio ----
const d = Router();
d.use(verifyJWT);
d.get("/stats", dashboard.getChannelStats);
d.get("/videos", dashboard.getChannelVideos);
api.use("/dashboard", d);

export default api;
