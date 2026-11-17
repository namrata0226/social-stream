import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { HiChevronLeft, HiChevronRight } from "react-icons/hi";
import { FaPlay } from "react-icons/fa";
import { mediaUrl } from "../api/client";
import { duration, timeAgo, views } from "../utils/format";
import MyListButton from "./MyListButton";

/** Row tile: lifts on hover with quick actions. */
function Tile({ video, rank }) {
  const navigate = useNavigate();
  const progress = video.progress;
  const pct = progress?.duration ? Math.min(100, (progress.position / progress.duration) * 100) : 0;

  return (
    <div className={`group/tile relative shrink-0 snap-start ${rank ? "w-[260px] sm:w-[300px]" : "w-[220px] sm:w-[280px]"}`}>
      <div className="flex items-end">
        {rank && (
          <span className="-mr-3 select-none bg-gradient-to-b from-brand-soft/70 to-glow/10 bg-clip-text font-display text-[104px] font-extrabold leading-[0.8] text-transparent">{rank}</span>
        )}
        <div
          role="link"
          tabIndex={0}
          onClick={() => navigate(`/watch/${video._id}`)}
          onKeyDown={(e) => e.key === "Enter" && navigate(`/watch/${video._id}`)}
          className="relative z-0 w-full cursor-pointer overflow-hidden rounded-2xl bg-ink-800 shadow-lg transition duration-300 group-hover/tile:z-10 group-hover/tile:-translate-y-1 group-hover/tile:shadow-2xl group-hover/tile:shadow-brand/25 group-hover/tile:ring-2 group-hover/tile:ring-brand/60"
        >
          <div className="relative aspect-video">
            <img src={mediaUrl(video.thumbnail)} alt="" loading="lazy" className="h-full w-full object-cover" />
            <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-black/10 to-transparent" />
            <span className="absolute right-1.5 top-1.5 rounded bg-black/70 px-1.5 py-0.5 text-[11px] font-semibold">{duration(video.duration)}</span>
            <div className="absolute inset-x-0 bottom-0 p-2.5">
              <p className="line-clamp-1 text-sm font-bold drop-shadow">{video.title}</p>
              <div className="mt-1 hidden items-center gap-2 group-hover/tile:flex">
                <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-brand to-indigo-500 text-white"><FaPlay size={11} className="ml-0.5" /></span>
                <MyListButton videoId={video._id} compact />
                <span className="ml-auto truncate text-[11px] text-zinc-300">{views(video.views)} · {timeAgo(video.createdAt)}</span>
              </div>
            </div>
            {pct > 0 && (
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/30">
                <div className="h-full bg-gradient-to-r from-brand to-glow" style={{ width: `${pct}%` }} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function VideoRow({ title, videos, link, ranked, extra }) {
  const scroller = useRef(null);
  const [atStart, setAtStart] = useState(true);
  const [atEnd, setAtEnd] = useState(false);

  const scroll = (dir) => scroller.current?.scrollBy({ left: dir * scroller.current.clientWidth * 0.85, behavior: "smooth" });
  const onScroll = () => {
    const el = scroller.current;
    setAtStart(el.scrollLeft < 10);
    setAtEnd(el.scrollLeft + el.clientWidth >= el.scrollWidth - 10);
  };

  return (
    <section className="group/row relative">
      <div className="mb-1 flex items-center gap-3 px-4 sm:px-8">
        <h2 className="font-display text-lg font-bold sm:text-xl">{title}</h2>
        {link && (
          <Link to={link} className="text-xs font-semibold text-brand-soft opacity-0 transition group-hover/row:opacity-100">
            See all ›
          </Link>
        )}
        {extra}
      </div>
      <div className="relative">
        <div ref={scroller} onScroll={onScroll} className="no-scrollbar flex snap-x gap-2 overflow-x-auto scroll-smooth px-4 py-3 sm:px-8">
          {videos.map((v, i) => (
            <Tile key={v._id} video={v} rank={ranked ? i + 1 : null} />
          ))}
        </div>
        {!atStart && (
          <button onClick={() => scroll(-1)} className="absolute bottom-3 left-0 top-3 z-20 hidden w-10 items-center justify-center bg-gradient-to-r from-ink-950 to-transparent opacity-0 transition hover:bg-black/80 group-hover/row:opacity-100 sm:flex" aria-label="Scroll left">
            <HiChevronLeft size={32} />
          </button>
        )}
        {!atEnd && videos.length > 3 && (
          <button onClick={() => scroll(1)} className="absolute bottom-3 right-0 top-3 z-20 hidden w-10 items-center justify-center bg-gradient-to-l from-ink-950 to-transparent opacity-0 transition hover:bg-black/80 group-hover/row:opacity-100 sm:flex" aria-label="Scroll right">
            <HiChevronRight size={32} />
          </button>
        )}
      </div>
    </section>
  );
}
