// Comments, reactions (likes/dislikes), subscriptions and community posts
import { Comment, Like, Post, Subscription, User, Video } from "../models/index.js";
import { ApiError } from "../utils/ApiError.js";
import { ok } from "../utils/ApiResponse.js";
import { ownerLookup, pageResult, paging, toId, videoCardProject } from "../utils/helpers.js";

// Adds likesCount / isLiked for any document type that can be liked
const likeStats = (field, userId) => [
  { $lookup: { from: "likes", localField: "_id", foreignField: field, as: "likes", pipeline: [{ $project: { likedBy: 1 } }] } },
  {
    $addFields: {
      likesCount: { $size: "$likes" },
      isLiked: userId ? { $in: [userId, "$likes.likedBy"] } : false,
    },
  },
  { $project: { likes: 0 } },
];

// ---------------- Comments ----------------

const commentPipeline = (match, sort, skip, limit, userId) => [
  { $match: match },
  ...likeStats("comment", userId),
  {
    $lookup: {
      from: "comments",
      localField: "_id",
      foreignField: "parent",
      as: "replies",
      pipeline: [{ $project: { _id: 1 } }],
    },
  },
  { $addFields: { replyCount: { $size: "$replies" } } },
  { $project: { replies: 0 } },
  { $sort: sort },
  { $skip: skip },
  { $limit: limit },
  ...ownerLookup(),
];

// GET /comments/video/:videoId?sort=newest|top
export const getVideoComments = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const { page, limit, skip } = paging(req.query, 20);
  const sort = req.query.sort === "top" ? { likesCount: -1, createdAt: -1 } : { createdAt: -1 };
  const match = { video: videoId, parent: null };
  const [docs, total] = await Promise.all([
    Comment.aggregate(commentPipeline(match, sort, skip, limit, req.user?._id)),
    Comment.countDocuments(match),
  ]);
  return ok(res, pageResult(docs, total, page, limit));
};

// GET /comments/:commentId/replies
export const getReplies = async (req, res) => {
  const parent = toId(req.params.commentId, "commentId");
  const { page, limit, skip } = paging(req.query, 50, 100);
  const match = { parent };
  const [docs, total] = await Promise.all([
    Comment.aggregate(commentPipeline(match, { createdAt: 1 }, skip, limit, req.user?._id)),
    Comment.countDocuments(match),
  ]);
  return ok(res, pageResult(docs, total, page, limit));
};

// POST /comments/video/:videoId { content, parentId? }
export const addComment = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const content = req.body.content?.trim();
  if (!content) throw new ApiError(400, "Comment cannot be empty");
  if (!(await Video.exists({ _id: videoId }))) throw new ApiError(404, "Video not found");

  let parent = null;
  if (req.body.parentId) {
    const parentComment = await Comment.findById(toId(req.body.parentId, "parentId"));
    if (!parentComment || !parentComment.video.equals(videoId)) throw new ApiError(404, "Parent comment not found");
    parent = parentComment.parent || parentComment._id; // keep threads one level deep
  }

  const comment = await Comment.create({ content, video: videoId, owner: req.user._id, parent });
  const [created] = await Comment.aggregate(commentPipeline({ _id: comment._id }, { createdAt: -1 }, 0, 1, req.user._id));
  return ok(res, created, "Comment added", 201);
};

const ownComment = async (req) => {
  const comment = await Comment.findById(toId(req.params.commentId, "commentId"));
  if (!comment) throw new ApiError(404, "Comment not found");
  return comment;
};

export const updateComment = async (req, res) => {
  const comment = await ownComment(req);
  if (!comment.owner.equals(req.user._id)) throw new ApiError(403, "You can only edit your own comments");
  const content = req.body.content?.trim();
  if (!content) throw new ApiError(400, "Comment cannot be empty");
  comment.content = content;
  comment.edited = true;
  await comment.save();
  return ok(res, comment, "Comment updated");
};

export const deleteComment = async (req, res) => {
  const comment = await ownComment(req);
  // the comment author or the video owner can delete
  const video = await Video.findById(comment.video).select("owner");
  if (!comment.owner.equals(req.user._id) && !video?.owner.equals(req.user._id)) {
    throw new ApiError(403, "You cannot delete this comment");
  }
  const ids = [comment._id, ...(await Comment.find({ parent: comment._id }).distinct("_id"))];
  await Promise.all([Comment.deleteMany({ _id: { $in: ids } }), Like.deleteMany({ comment: { $in: ids } })]);
  return ok(res, { deleted: ids.length }, "Comment deleted");
};

// ---------------- Likes ----------------

// POST /likes/video/:videoId { type: "like" | "dislike" } — clicking the same reaction again removes it
export const reactToVideo = async (req, res) => {
  const videoId = toId(req.params.videoId, "videoId");
  const type = req.body?.type === "dislike" ? "dislike" : "like";
  if (!(await Video.exists({ _id: videoId }))) throw new ApiError(404, "Video not found");

  const existing = await Like.findOne({ video: videoId, likedBy: req.user._id });
  let myReaction = type;
  if (existing?.type === type) {
    await existing.deleteOne();
    myReaction = null;
  } else if (existing) {
    existing.type = type;
    await existing.save();
  } else {
    await Like.create({ video: videoId, likedBy: req.user._id, type });
  }
  const [likesCount, dislikesCount] = await Promise.all([
    Like.countDocuments({ video: videoId, type: "like" }),
    Like.countDocuments({ video: videoId, type: "dislike" }),
  ]);
  return ok(res, { myReaction, likesCount, dislikesCount });
};

const toggleLike = (field, Model) => async (req, res) => {
  const id = toId(req.params.id, `${field}Id`);
  if (!(await Model.exists({ _id: id }))) throw new ApiError(404, `${field} not found`);
  const removed = await Like.findOneAndDelete({ [field]: id, likedBy: req.user._id });
  if (!removed) await Like.create({ [field]: id, likedBy: req.user._id });
  const likesCount = await Like.countDocuments({ [field]: id });
  return ok(res, { isLiked: !removed, likesCount });
};
export const toggleCommentLike = toggleLike("comment", Comment);
export const togglePostLike = toggleLike("post", Post);

// GET /likes/videos
export const getLikedVideos = async (req, res) => {
  const docs = await Like.aggregate([
    { $match: { likedBy: req.user._id, video: { $exists: true }, type: "like" } },
    { $sort: { createdAt: -1 } },
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
    { $replaceRoot: { newRoot: "$video" } },
  ]);
  return ok(res, docs);
};

// ---------------- Subscriptions ----------------

// POST /subscriptions/c/:channelId
export const toggleSubscription = async (req, res) => {
  const channel = toId(req.params.channelId, "channelId");
  if (channel.equals(req.user._id)) throw new ApiError(400, "You cannot subscribe to yourself");
  if (!(await User.exists({ _id: channel }))) throw new ApiError(404, "Channel not found");
  const removed = await Subscription.findOneAndDelete({ channel, subscriber: req.user._id });
  if (!removed) await Subscription.create({ channel, subscriber: req.user._id });
  const subscribersCount = await Subscription.countDocuments({ channel });
  return ok(res, { isSubscribed: !removed, subscribersCount }, removed ? "Unfollowed" : "Following");
};

const channelCard = (localField) => [
  {
    $lookup: {
      from: "users",
      localField,
      foreignField: "_id",
      as: "channel",
      pipeline: [
        { $lookup: { from: "subscriptions", localField: "_id", foreignField: "channel", as: "subs" } },
        { $addFields: { subscribersCount: { $size: "$subs" } } },
        { $project: { username: 1, fullName: 1, avatar: 1, bio: 1, subscribersCount: 1 } },
      ],
    },
  },
  { $unwind: "$channel" },
  { $replaceRoot: { newRoot: "$channel" } },
];

// GET /subscriptions/channels — channels the current user follows
export const getSubscribedChannels = async (req, res) => {
  const docs = await Subscription.aggregate([
    { $match: { subscriber: req.user._id } },
    { $sort: { createdAt: -1 } },
    ...channelCard("channel"),
  ]);
  return ok(res, docs);
};

// GET /subscriptions/c/:channelId/subscribers
export const getChannelSubscribers = async (req, res) => {
  const channel = toId(req.params.channelId, "channelId");
  const docs = await Subscription.aggregate([
    { $match: { channel } },
    { $sort: { createdAt: -1 } },
    { $limit: 200 },
    ...channelCard("subscriber"),
  ]);
  return ok(res, docs);
};

// GET /subscriptions/feed — latest videos from followed channels
export const getSubscriptionFeed = async (req, res) => {
  const { page, limit, skip } = paging(req.query, 24);
  const channels = await Subscription.find({ subscriber: req.user._id }).distinct("channel");
  const match = { owner: { $in: channels }, isPublished: true };
  const [docs, total] = await Promise.all([
    Video.aggregate([
      { $match: match },
      { $sort: { createdAt: -1 } },
      { $skip: skip },
      { $limit: limit },
      ...ownerLookup(),
      { $project: videoCardProject },
    ]),
    Video.countDocuments(match),
  ]);
  return ok(res, pageResult(docs, total, page, limit));
};

// ---------------- Community posts ----------------

export const getUserPosts = async (req, res) => {
  const owner = toId(req.params.userId, "userId");
  const docs = await Post.aggregate([
    { $match: { owner } },
    { $sort: { createdAt: -1 } },
    { $limit: 100 },
    ...likeStats("post", req.user?._id),
    ...ownerLookup(),
  ]);
  return ok(res, docs);
};

export const createPost = async (req, res) => {
  const content = req.body.content?.trim();
  if (!content) throw new ApiError(400, "Post cannot be empty");
  const post = await Post.create({ content, owner: req.user._id });
  return ok(res, post, "Post published", 201);
};

const ownPost = async (req) => {
  const post = await Post.findById(toId(req.params.postId, "postId"));
  if (!post) throw new ApiError(404, "Post not found");
  if (!post.owner.equals(req.user._id)) throw new ApiError(403, "You can only modify your own posts");
  return post;
};

export const updatePost = async (req, res) => {
  const post = await ownPost(req);
  const content = req.body.content?.trim();
  if (!content) throw new ApiError(400, "Post cannot be empty");
  post.content = content;
  await post.save();
  return ok(res, post, "Post updated");
};

export const deletePost = async (req, res) => {
  const post = await ownPost(req);
  await Promise.all([post.deleteOne(), Like.deleteMany({ post: post._id })]);
  return ok(res, {}, "Post deleted");
};
