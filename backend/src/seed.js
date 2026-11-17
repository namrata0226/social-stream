// Demo content so the app isn't empty on first run.
// Runs automatically on startup when the database has no videos (disable with SEED_DEMO=false),
// or manually with `npm run seed` while the API is stopped.
import { User, Video, Comment, Subscription, Post, Playlist, Like } from "./models/index.js";

const ext = (url) => ({ url, public_id: null, provider: "external" });
const thumb = (seed) => ext(`https://picsum.photos/seed/${seed}/1280/720`);
const avatar = (seed) => ext(`https://api.dicebear.com/9.x/thumbs/svg?seed=${seed}`);

// Openly licensed sample clips (Blender Foundation CC-BY, MDN CC0, samplelib free samples)
const CLIPS = {
  sintel: { url: "https://download.blender.org/durian/trailer/sintel_trailer-720p.mp4", duration: 52 },
  bunny: {
    url: "https://upload.wikimedia.org/wikipedia/commons/transcoded/c/c0/Big_Buck_Bunny_4K.webm/Big_Buck_Bunny_4K.webm.480p.vp9.webm",
    duration: 635,
  },
  flower: { url: "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4", duration: 5 },
  friday: { url: "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/friday.mp4", duration: 9 },
  rabbit: {
    url: "https://mdn.github.io/learning-area/html/multimedia-and-embedding/video-and-audio-content/rabbit320.mp4",
    duration: 4,
  },
  s10: { url: "https://download.samplelib.com/mp4/sample-10s.mp4", duration: 10 },
  s15: { url: "https://download.samplelib.com/mp4/sample-15s.mp4", duration: 15 },
  s20: { url: "https://download.samplelib.com/mp4/sample-20s.mp4", duration: 20 },
};

const VIDEOS = [
  ["Sintel — Official Trailer", "A lonely young woman searches for her dragon friend in this Blender open movie.", "Movies", "sintel", ["animation", "fantasy", "blender"], 0, true],
  ["Big Buck Bunny (Full Short Film)", "A giant rabbit takes revenge on three bullying rodents. Blender Foundation open movie.\n\nChapters\n0:00 Opening\n1:30 Meet Bunny\n3:10 The bullies arrive\n6:00 Bunny's plan\n8:20 Payback\n10:00 Credits", "Movies", "bunny", ["animation", "comedy", "blender"], 0],
  ["Spring Bloom in Slow Motion", "Relaxing close-up of a flower moving in the breeze.", "Travel", "flower", ["nature", "relax"], 1],
  ["Friday Night Vibes", "Short city mood clip to start your weekend.", "Lifestyle", "friday", ["city", "weekend"], 1],
  ["Rabbit Encounter", "A tiny wildlife moment caught on camera.", "Travel", "rabbit", ["wildlife", "nature"], 1],
  ["City Traffic Timelapse", "Highways and lights — a quick timelapse.", "Travel", "s10", ["timelapse", "city"], 2],
  ["Morning Coffee Routine", "Brew the perfect cup in 15 seconds.", "Food", "s15", ["coffee", "morning"], 2],
  ["Beach Drone Shots", "Waves, sand and sunshine from above.", "Travel", "s20", ["drone", "beach"], 2],
  ["Learn React in 60 Seconds", "Components, props and state — the absolute basics.", "Education", "s15", ["react", "javascript", "webdev"], 0],
  ["Top 5 Indie Games This Year", "Our favourite small-studio releases.", "Gaming", "s20", ["indie", "games"], 2],
  ["Lo-fi Beats to Study To", "Chill background music for focus sessions.", "Music", "s10", ["lofi", "study", "music"], 1],
  ["Stand-up: Developers on Monday", "A short comedy bit about deploys and coffee.", "Comedy", "friday", ["standup", "developers"], 0],
  ["Matchday Highlights", "Every goal from the weekend in seconds.", "Sports", "s20", ["football", "highlights"], 2],
  ["Gadget Unboxing: Tiny Camera", "Is this the smallest action cam ever?", "Technology", "s10", ["unboxing", "tech"], 0],
  ["Street Food Tour", "Five snacks you must try.", "Food", "s15", ["streetfood", "travel"], 1],
  ["Sintel — Behind the Dragon", "How the dragon scenes were made.", "Movies", "sintel", ["animation", "making-of"], 0],
];

const CREATORS = [
  { username: "demo", fullName: "Demo Creator", email: "demo@socialstream.dev", bio: "Official demo channel. Sign in with demo / demo123." },
  { username: "travelnest", fullName: "Travel Nest", email: "travel@socialstream.dev", bio: "Short travel and nature clips." },
  { username: "dailybytes", fullName: "Daily Bytes", email: "bytes@socialstream.dev", bio: "Food, sport and everyday moments." },
];

export async function seedDemo({ force = false } = {}) {
  if (!force && (await Video.estimatedDocumentCount()) > 0) return false;

  const users = [];
  for (const c of CREATORS) {
    let user = await User.findOne({ username: c.username });
    if (!user) user = await User.create({ ...c, password: "demo123", avatar: avatar(c.username), coverImage: thumb(`${c.username}-cover`) });
    users.push(user);
  }

  const now = Date.now();
  const videos = [];
  for (const [i, [title, description, category, clip, tags, ownerIdx, featured]] of VIDEOS.entries()) {
    const createdAt = new Date(now - i * 26 * 60 * 60 * 1000);
    videos.push(
      await Video.create({
        title,
        description,
        category,
        tags,
        owner: users[ownerIdx]._id,
        videoFile: ext(CLIPS[clip].url),
        thumbnail: thumb(`ss-${i}`),
        duration: CLIPS[clip].duration,
        views: Math.floor(Math.random() * 50000) + 100,
        isFeatured: Boolean(featured),
        createdAt,
        updatedAt: createdAt,
      })
    );
  }

  await Subscription.create([
    { subscriber: users[0]._id, channel: users[1]._id },
    { subscriber: users[0]._id, channel: users[2]._id },
    { subscriber: users[1]._id, channel: users[0]._id },
    { subscriber: users[2]._id, channel: users[0]._id },
  ]);
  const c1 = await Comment.create({ content: "The dragon scenes are stunning 🐉", video: videos[0]._id, owner: users[1]._id });
  await Comment.create({ content: "Agreed! The music too.", video: videos[0]._id, owner: users[2]._id, parent: c1._id });
  await Comment.create({ content: "Classic. Never gets old.", video: videos[1]._id, owner: users[2]._id });
  await Like.create([
    { video: videos[0]._id, likedBy: users[1]._id, type: "like" },
    { video: videos[0]._id, likedBy: users[2]._id, type: "like" },
    { comment: c1._id, likedBy: users[0]._id },
  ]);
  await Post.create({ content: "Welcome to Kinora! New videos every week — follow along, and drop a Moment 🔥 when something hits.", owner: users[0]._id });
  await Playlist.create({
    name: "Open Movies",
    description: "Blender Foundation films",
    owner: users[0]._id,
    videos: [videos[0]._id, videos[1]._id, videos[15]._id],
  });

  console.log(`🌱 Seeded demo data: ${users.length} channels, ${videos.length} videos (login: demo / demo123)`);
  return true;
}

// `npm run seed`
if (import.meta.url === `file://${process.argv[1]}`) {
  const { connectDB, disconnectDB } = await import("./db.js");
  await connectDB();
  const done = await seedDemo({ force: process.argv.includes("--force") });
  if (!done) console.log("Database already has videos — skipping (use `npm run seed -- --force`).");
  await disconnectDB();
}
