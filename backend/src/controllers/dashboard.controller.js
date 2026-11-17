import { Comment, Like, Subscription, Video } from "../models/index.js";
import { ok } from "../utils/ApiResponse.js";

// GET /dashboard/stats
export const getChannelStats = async (req, res) => {
  const owner = req.user._id;
  const videoIds = await Video.find({ owner }).distinct("_id");
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [videoAgg, subscribers, newSubscribers, likes, comments, top] = await Promise.all([
    Video.aggregate([
      { $match: { owner } },
      {
        $group: {
          _id: null,
          totalVideos: { $sum: 1 },
          published: { $sum: { $cond: ["$isPublished", 1, 0] } },
          totalViews: { $sum: "$views" },
          totalDuration: { $sum: "$duration" },
        },
      },
    ]),
    Subscription.countDocuments({ channel: owner }),
    Subscription.countDocuments({ channel: owner, createdAt: { $gte: since } }),
    Like.countDocuments({ video: { $in: videoIds }, type: "like" }),
    Comment.countDocuments({ video: { $in: videoIds } }),
    Video.find({ owner }).sort({ views: -1 }).limit(5).select("title views thumbnail createdAt"),
  ]);

  const v = videoAgg[0] || {};
  return ok(res, {
    totalVideos: v.totalVideos || 0,
    publishedVideos: v.published || 0,
    totalViews: v.totalViews || 0,
    totalDuration: v.totalDuration || 0,
    totalSubscribers: subscribers,
    newSubscribers30d: newSubscribers,
    totalLikes: likes,
    totalComments: comments,
    topVideos: top,
  });
};

// GET /dashboard/videos — all of the creator's videos (including drafts) with engagement numbers
export const getChannelVideos = async (req, res) => {
  const videos = await Video.aggregate([
    { $match: { owner: req.user._id } },
    { $sort: { createdAt: -1 } },
    {
      $lookup: {
        from: "likes",
        localField: "_id",
        foreignField: "video",
        as: "reactions",
        pipeline: [{ $project: { type: 1 } }],
      },
    },
    { $lookup: { from: "comments", localField: "_id", foreignField: "video", as: "comments", pipeline: [{ $project: { _id: 1 } }] } },
    {
      $addFields: {
        likesCount: { $size: { $filter: { input: "$reactions", cond: { $eq: ["$$this.type", "like"] } } } },
        dislikesCount: { $size: { $filter: { input: "$reactions", cond: { $eq: ["$$this.type", "dislike"] } } } },
        commentsCount: { $size: "$comments" },
      },
    },
    { $project: { reactions: 0, comments: 0, videoFile: 0 } },
  ]);
  return ok(res, videos);
};
