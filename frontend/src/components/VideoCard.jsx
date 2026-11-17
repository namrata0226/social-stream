import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { mediaUrl } from "../api/client";
import { duration, timeAgo, views } from "../utils/format";
import { Avatar } from "./ui";

export function Thumb({ video, progress, className = "", rounded = "rounded-xl" }) {
  const pct = progress?.duration ? Math.min(100, (progress.position / progress.duration) * 100) : 0;
  return (
    <div className={`relative aspect-video overflow-hidden bg-ink-800 ${rounded} ${className}`}>
      <img src={mediaUrl(video.thumbnail)} alt="" loading="lazy" className="h-full w-full object-cover transition duration-300 group-hover:scale-105" />
      {video.duration > 0 && (
        <span className="absolute bottom-1.5 right-1.5 rounded bg-black/80 px-1.5 py-0.5 text-xs font-semibold">{duration(video.duration)}</span>
      )}
      {video.isPublished === false && (
        <span className="absolute left-1.5 top-1.5 rounded bg-amber-500 px-1.5 py-0.5 text-xs font-bold text-black">Draft</span>
      )}
      {pct > 0 && (
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/30">
          <div className="h-full bg-brand" style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  );
}

/** Grid card with a muted hover preview. */
export function VideoCard({ video, progress, actions }) {
  const [preview, setPreview] = useState(false);
  const timer = useRef(null);
  const navigate = useNavigate();
  const to = `/watch/${video._id}`;

  return (
    <div
      className="group relative animate-fadeIn"
      onMouseEnter={() => (timer.current = setTimeout(() => setPreview(true), 700))}
      onMouseLeave={() => (clearTimeout(timer.current), setPreview(false))}
    >
      <Link to={to} className="relative block">
        <Thumb video={video} progress={progress} />
        {preview && video.videoFile?.url && (
          <video src={mediaUrl(video.videoFile)} autoPlay muted loop playsInline className="absolute inset-0 h-full w-full rounded-xl object-cover" />
        )}
      </Link>
      <div className="mt-3 flex gap-3">
        <Avatar user={video.owner} link />
        <div className="min-w-0 flex-1">
          <Link to={to} className="line-clamp-2 font-semibold leading-snug" title={video.title}>{video.title}</Link>
          <button className="mt-1 block truncate text-sm text-zinc-400 hover:text-white" onClick={() => navigate(`/c/${video.owner?.username}`)}>
            {video.owner?.fullName}
          </button>
          <p className="text-sm text-zinc-400">
            {views(video.views)} · {timeAgo(video.createdAt)}
          </p>
        </div>
        {actions}
      </div>
    </div>
  );
}

/** Compact horizontal card used in "Up next" and search results. */
export function VideoListItem({ video, large, active, index }) {
  return (
    <Link to={`/watch/${video._id}`} className={`group flex gap-3 rounded-xl p-1.5 transition hover:bg-white/5 ${active ? "bg-white/10" : ""}`}>
      {index !== undefined && <span className="w-5 shrink-0 self-center text-center text-sm text-zinc-500">{index + 1}</span>}
      <Thumb video={video} className={large ? "w-64 shrink-0 sm:w-80" : "w-40 shrink-0"} />
      <div className="min-w-0 flex-1 py-0.5">
        <p className={`line-clamp-2 font-semibold leading-snug ${large ? "text-lg" : "text-sm"}`}>{video.title}</p>
        <p className="mt-1 truncate text-xs text-zinc-400">{video.owner?.fullName}</p>
        <p className="text-xs text-zinc-400">{views(video.views)} · {timeAgo(video.createdAt)}</p>
        {large && video.description && <p className="mt-2 line-clamp-2 text-sm text-zinc-400">{video.description}</p>}
      </div>
    </Link>
  );
}

export function VideoGrid({ videos, renderActions }) {
  return (
    <div className="grid gap-x-4 gap-y-8 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {videos.map((v) => (
        <VideoCard key={v._id} video={v} progress={v.progress} actions={renderActions?.(v)} />
      ))}
    </div>
  );
}
