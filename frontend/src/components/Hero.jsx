import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { FaPlay } from "react-icons/fa";
import { HiVolumeOff, HiVolumeUp } from "react-icons/hi";
import { mediaUrl } from "../api/client";
import { duration, views } from "../utils/format";
import MyListButton from "./MyListButton";
import { Avatar } from "./ui";

/** "Spotlight": an inset featured card that auto-rotates and plays a muted preview. */
export default function Hero({ items }) {
  const [index, setIndex] = useState(0);
  const [muted, setMuted] = useState(true);
  const [videoReady, setVideoReady] = useState(false);
  const video = items[index];

  useEffect(() => {
    setVideoReady(false);
    if (items.length < 2) return;
    const t = setTimeout(() => setIndex((i) => (i + 1) % items.length), 15000);
    return () => clearTimeout(t);
  }, [index, items.length]);

  if (!video) return null;

  return (
    <section className="relative mx-3 mt-3 h-[58vh] min-h-[400px] overflow-hidden rounded-3xl ring-1 ring-white/10 sm:mx-6 sm:mt-5 sm:h-[64vh]">
      <img key={video._id} src={mediaUrl(video.thumbnail)} alt="" className={`absolute inset-0 h-full w-full object-cover transition-opacity duration-700 animate-fadeIn ${videoReady ? "opacity-0" : "opacity-100"}`} />
      {video.videoFile?.url && (
        <video
          key={`v-${video._id}`}
          src={mediaUrl(video.videoFile)}
          autoPlay
          muted={muted}
          loop
          playsInline
          onPlaying={() => setVideoReady(true)}
          className={`absolute inset-0 h-full w-full object-cover transition-opacity duration-1000 ${videoReady ? "opacity-100" : "opacity-0"}`}
        />
      )}
      <div className="absolute inset-0 bg-gradient-to-r from-ink-950/95 via-ink-950/50 to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-2/3 bg-gradient-to-t from-ink-950/90 to-transparent" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_rgba(139,92,246,0.35),_transparent_55%)]" />

      <div key={`t-${video._id}`} className="absolute bottom-10 left-5 right-5 max-w-xl animate-rise sm:bottom-14 sm:left-10">
        <div className="mb-3 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-glow-soft">
          <span className="rounded-full bg-aurora px-2.5 py-0.5 text-[10px] tracking-wider text-white">✦ Spotlight</span>
          {video.category}
        </div>
        <h1 className="font-display text-3xl font-extrabold leading-tight drop-shadow-lg sm:text-5xl">{video.title}</h1>
        <div className="mt-3 flex items-center gap-3 text-sm text-zinc-300">
          <Avatar user={video.owner} size="h-6 w-6" link />
          <Link to={`/c/${video.owner?.username}`} className="font-semibold hover:underline">{video.owner?.fullName}</Link>
          <span>·</span>
          <span>{views(video.views)}</span>
          <span>·</span>
          <span>{duration(video.duration)}</span>
        </div>
        <p className="mt-3 line-clamp-3 text-sm text-zinc-200 drop-shadow sm:text-base">{video.description}</p>
        <div className="mt-5 flex flex-wrap gap-3">
          <Link to={`/watch/${video._id}`} className="btn-primary px-6 py-2.5 text-base"><FaPlay /> Watch now</Link>
          <MyListButton videoId={video._id} />
        </div>
      </div>

      <div className="absolute right-4 top-4 flex items-center gap-3 sm:right-6 sm:top-6">
        <button className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/20 bg-black/40 backdrop-blur hover:bg-black/60" onClick={() => setMuted((m) => !m)} aria-label="Toggle sound">
          {muted ? <HiVolumeOff size={18} /> : <HiVolumeUp size={18} />}
        </button>
      </div>

      {items.length > 1 && (
        <div className="absolute bottom-6 right-6 hidden gap-2 sm:flex">
          {items.map((v, i) => (
            <button key={v._id} onClick={() => setIndex(i)} aria-label={`Show ${v.title}`} className={`h-1.5 rounded-full transition-all ${i === index ? "w-8 bg-aurora" : "w-3 bg-white/40 hover:bg-white/70"}`} />
          ))}
        </div>
      )}
    </section>
  );
}
