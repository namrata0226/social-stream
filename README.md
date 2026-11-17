# Kinora

> Watch together, one moment at a time.

A full-stack video platform: upload and watch videos, follow creators, react with Moments and keep notes, with community features (loves, comments, follows, playlists), plus a browsing experience with a spotlight banner, themed rows, a watchlist and resume-where-you-left-off.

**Stack:** React 18 + Vite + Tailwind + Redux Toolkit · Node/Express 5 + MongoDB (Mongoose) · JWT auth with httpOnly cookies · local disk or Cloudinary storage

## What makes Kinora different

- **Moments**: tap an emoji (🔥 😂 😮 ❤️ 👏 🤯) to pin a reaction to the exact second of a video. Everyone's Moments float across the player as they watch, and a heat strip above the seek bar shows where the crowd reacted most.
- **Private timestamped notes**: write notes while you watch, and each one remembers its timestamp. The **My Notes** page collects every note, is searchable, and links straight back to that second.
- **Chapters**: write lines like `0:00 Intro` / `1:30 Setup` in a description and the player shows chapter markers, chapter names on hover and a clickable chapter strip. Any timestamp in a description is clickable.
- **Mood picker**: "What's your vibe?" (Chill, Learn, Laugh, Hype, Cinematic, Hungry, Curious) finds videos to match, with a mood-aware shuffle.
- **Shuffle**: the 🎲 button, or press `S`, plays something random.
- **Share at a timestamp**: share links can start at the current second (`?t=95`).

## Quick start

Requires Node 18+.

```bash
npm run setup   # installs everything and creates backend/.env with random JWT secrets
npm run dev     # API on http://localhost:8000, web app on http://localhost:5173
```

Open http://localhost:5173 and sign in with **demo / demo123**, or create an account.

No database setup is needed: if `MONGODB_URI` is empty, the API starts an embedded MongoDB that stores its data in `backend/data/db`. On first start it seeds demo channels and openly licensed sample videos. To turn seeding off, set `SEED_DEMO=false`.

## Configuration (`backend/.env`)

| Variable | Purpose |
| --- | --- |
| `MONGODB_URI` | MongoDB/Atlas connection string. Empty means use the embedded DB |
| `ACCESS_TOKEN_SECRET`, `REFRESH_TOKEN_SECRET` | JWT signing secrets (required in production) |
| `CORS_ORIGIN` | Allowed frontend origin(s), comma-separated |
| `CLOUDINARY_*` | When all three are set, uploads go to Cloudinary instead of `backend/uploads/` |
| `MAX_UPLOAD_MB` | Upload size limit (default 1024) |
| `MONGOMS_VERSION` | Embedded MongoDB version (default 7.0.14, which works on macOS 12+) |

For a separate frontend deployment, set `VITE_API_URL` in `frontend/.env` to the API origin.

## Features

**Watching**
- Custom player with seek preview bar, buffering indicator, speed control (0.25–2x), picture-in-picture, theater mode, and fullscreen
- Keyboard shortcuts: Space/K, J/L, ←/→, ↑/↓, M, F, T, I, N, 0–9, Shift+</>
- **Resume playback** from where you left off, with a "Start over" option
- **Autoplay next**, with a countdown and cancel; plays through playlists in order
- Muted autoplay fallback with "Tap to unmute" when the browser blocks sound
- View counting that ignores repeat views from the same user within 6 hours

**Discovery**
- Auto-rotating featured hero with a muted video preview, Play / My List / More info
- Rows: Continue Watching (with progress bars), My List, From Your Subscriptions, Trending Now (Top-10 style numbers), New Releases, Most Watched, plus a row per category
- Hover tiles with quick play and add-to-list
- **My List** (watch later)

**Community**
- Like / dislike, subscribe, share (native share sheet or copy link)
- Comments with replies, comment likes, edit/delete (video owners can moderate), and Newest/Top sorting
- Channel pages with Videos / Playlists / Community posts / About tabs
- Playlists: public or private, Play all, Shuffle, save from any video
- Search across titles, descriptions, tags, and channel names, with category and sort filters; recent searches are remembered; press `/` to focus the search box
- Explore page with category chips and infinite scroll
- Hover-to-preview on video cards

**Creators**
- Drag-and-drop upload with progress bar and cancel. Duration is detected automatically, and 3 thumbnail options are generated from video frames (or upload your own)
- Categories, tags, and public/draft visibility
- Creator Studio: views, subscribers (+30-day change), likes, comments, content length; per-video stats, publish toggle, edit (including thumbnail), delete (cleans up comments, likes, history, and files)
- Settings: profile, avatar, cover image, password

**Library:** watch history grouped by day (remove one or clear all), liked videos, subscriptions feed

## API overview (`/api/v1`)

| Area | Endpoints |
| --- | --- |
| users | `POST /users/register` `POST /users/login` `POST /users/logout` `POST /users/refresh-token` `GET /users/session` `GET/PATCH /users/me` `PATCH /users/me/avatar` `PATCH /users/me/cover` `POST /users/me/password` `GET /users/c/:username` `GET/DELETE /users/history` `DELETE /users/history/:videoId` `GET /users/continue-watching` `GET /users/my-list` `POST /users/my-list/:videoId` |
| videos | `GET /videos` (q, category, owner, sort, page, limit) `GET /videos/browse` `GET /videos/categories` `POST /videos` `GET/PATCH/DELETE /videos/:id` `PATCH /videos/:id/publish` `POST /videos/:id/view` `POST /videos/:id/progress` `GET /videos/:id/related` |
| comments | `GET/POST /comments/video/:videoId` `GET /comments/:id/replies` `PATCH/DELETE /comments/:id` |
| likes | `POST /likes/video/:id` (`{type:"like"\|"dislike"}`) `POST /likes/comment/:id` `POST /likes/post/:id` `GET /likes/videos` |
| subscriptions | `POST /subscriptions/c/:channelId` `GET /subscriptions/c/:channelId/subscribers` `GET /subscriptions/channels` `GET /subscriptions/feed` |
| posts | `GET /posts/user/:userId` `POST /posts` `PATCH/DELETE /posts/:id` |
| playlists | `GET /playlists/user/:userId` `POST /playlists` `GET/PATCH/DELETE /playlists/:id` `POST /playlists/:id/videos/:videoId` |
| dashboard | `GET /dashboard/stats` `GET /dashboard/videos` |

Errors always use the shape `{ success: false, statusCode, message, errors }` with the correct HTTP status.

## Production notes
- Set `NODE_ENV=production`, real JWT secrets, `MONGODB_URI`, and `CORS_ORIGIN`. Cookies then become `Secure; SameSite=None` for cross-site use.
- On hosts with ephemeral disks (Vercel, Render free tier, etc.), configure Cloudinary so uploads persist.
- `npm run build` outputs the frontend to `frontend/dist`. Serve it with an SPA fallback (see `frontend/vercel.json`).
