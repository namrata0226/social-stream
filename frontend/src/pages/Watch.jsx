import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import toast from "react-hot-toast";
import { BiDislike, BiSolidDislike } from "react-icons/bi";
import { RiHeart3Line, RiHeart3Fill, RiUserFollowLine, RiUserHeartFill } from "react-icons/ri";
import { GiPerspectiveDiceSixFacesRandom } from "react-icons/gi";
import { RiShareForwardLine } from "react-icons/ri";
import { MdPlaylistAdd, MdOutlineEdit } from "react-icons/md";
import { api, errMsg, mediaUrl } from "../api/client";
import { useAuthGuard, useFetch, useShuffle, useUser } from "../hooks";
import { BRAND } from "../brand";
import { parseChapters, parseTime, TIMESTAMP_RE } from "../utils/chapters";
import { ChapterStrip, MomentsBar, NotesPanel, ShareModal } from "../components/WatchExtras";
import { compact, fullDate, timeAgo, views } from "../utils/format";
import VideoPlayer from "../components/VideoPlayer";
import Comments from "../components/Comments";
import SaveToPlaylist from "../components/SaveToPlaylist";
import MyListButton from "../components/MyListButton";
import { VideoListItem } from "../components/VideoCard";
import { Avatar, ErrorState, PageSpinner, Toggle } from "../components/ui";

const pref = (k, d) => {
  try {
    const v = localStorage.getItem(k);
    return v === null ? d : v === "true";
  } catch {
    return d;
  }
};
const setPref = (k, v) => {
  try {
    localStorage.setItem(k, String(v));
  } catch {}
};

export function SubscribeButton({ channel, onChange }) {
  const user = useUser();
  const guard = useAuthGuard();
  const [busy, setBusy] = useState(false);
  if (user && user._id === channel._id) return null;

  const toggle = guard(async () => {
    setBusy(true);
    try {
      const { data } = await api.post(`/subscriptions/c/${channel._id}`);
      onChange(data.data);
      toast.success(data.message);
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  });

  return (
    <button onClick={toggle} disabled={busy} className={channel.isSubscribed ? "btn-ghost" : "btn-primary"}>
      {channel.isSubscribed ? <><RiUserHeartFill className="text-brand-soft" /> Following</> : <><RiUserFollowLine /> Follow</>}
    </button>
  );
}

// Turns "1:30" in text into buttons that seek the player
function Linkified({ text, onSeek }) {
  const parts = [];
  let last = 0;
  for (const m of text.matchAll(TIMESTAMP_RE)) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const t = parseTime(m[0]);
    parts.push(
      <button key={m.index} className="font-semibold text-glow-soft hover:underline" onClick={(e) => (e.stopPropagation(), onSeek(t))}>{m[0]}</button>
    );
    last = m.index + m[0].length;
  }
  parts.push(text.slice(last));
  return parts;
}

function Description({ video, onSeek }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`mt-4 rounded-2xl bg-ink-800/80 p-4 text-sm ${open ? "" : "cursor-pointer hover:bg-ink-700/80"}`} onClick={() => !open && setOpen(true)}>
      <p className="font-semibold">
        {open ? `${video.views.toLocaleString()} views` : views(video.views)} · {open ? fullDate(video.createdAt) : timeAgo(video.createdAt)}
        <Link to={`/explore?category=${video.category}`} className="ml-2 text-brand-soft hover:underline" onClick={(e) => e.stopPropagation()}>#{video.category}</Link>
        {video.tags?.map((t) => (
          <Link key={t} to={`/search?q=${encodeURIComponent(t)}`} onClick={(e) => e.stopPropagation()} className="ml-2 text-brand-soft hover:underline">#{t}</Link>
        ))}
      </p>
      <p className={`mt-2 whitespace-pre-wrap break-words ${open ? "" : "line-clamp-2"}`}>{video.description ? <Linkified text={video.description} onSeek={onSeek} /> : "No description."}</p>
      <button className="mt-2 font-semibold" onClick={(e) => (e.stopPropagation(), setOpen((o) => !o))}>{open ? "Show less" : "…more"}</button>
    </div>
  );
}

function PlaylistPanel({ playlist, currentId }) {
  const idx = playlist.videos.findIndex((v) => v._id === currentId);
  return (
    <div className="mb-4 overflow-hidden rounded-xl border border-ink-700">
      <div className="bg-ink-800 px-4 py-3">
        <Link to={`/playlist/${playlist._id}`} className="font-bold hover:underline">{playlist.name}</Link>
        <p className="text-xs text-zinc-400">{playlist.owner?.fullName} · {idx + 1}/{playlist.videos.length}</p>
      </div>
      <div className="max-h-96 overflow-y-auto p-1">
        {playlist.videos.map((v, i) => (
          <Link key={v._id} to={`/watch/${v._id}?list=${playlist._id}`} className={`flex gap-2 rounded-lg p-1.5 hover:bg-white/5 ${v._id === currentId ? "bg-white/10" : ""}`}>
            <span className="w-5 shrink-0 self-center text-center text-xs text-zinc-500">{v._id === currentId ? "▶" : i + 1}</span>
            <img src={mediaUrl(v.thumbnail)} alt="" className="aspect-video w-24 shrink-0 rounded object-cover" />
            <div className="min-w-0">
              <p className="line-clamp-2 text-xs font-semibold">{v.title}</p>
              <p className="truncate text-[11px] text-zinc-400">{v.owner?.fullName}</p>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

export default function Watch() {
  const { videoId } = useParams();
  const [params] = useSearchParams();
  const listId = params.get("list");
  const navigate = useNavigate();
  const user = useUser();
  const guard = useAuthGuard();

  const { data: video, setData: setVideo, loading, error, reload } = useFetch(`/videos/${videoId}`);
  const { data: related } = useFetch(`/videos/${videoId}/related`);
  const { data: playlist } = useFetch(listId ? `/playlists/${listId}` : null);
  const [theater, setTheater] = useState(() => pref("kn.theater", false));
  const [autoplay, setAutoplay] = useState(() => pref("kn.autoplay", true));
  const [saveOpen, setSaveOpen] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);
  const [tab, setTab] = useState("comments");
  const [showMoments, setShowMoments] = useState(() => pref("kn.moments", true));
  const shuffle = useShuffle();
  const playerRef = useRef(null);
  const getTime = useCallback(() => playerRef.current?.getTime() || 0, []);
  const seekTo = useCallback((t) => {
    playerRef.current?.seekTo(t);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const { data: momentsRaw, setData: setMoments } = useFetch(`/moments/video/${videoId}`);
  const moments = momentsRaw && { ...momentsRaw, videoId };
  const addMoment = useCallback(
    (m, burst) => {
      if (burst) playerRef.current?.burst(m.e);
      setMoments((d) => {
        if (!d) return d;
        const buckets = [...d.buckets];
        const i = buckets.findIndex((b) => b.t === m.t && b.e === m.e);
        if (i >= 0) buckets[i] = { ...buckets[i], n: buckets[i].n + m.n };
        else if (m.n > 0) buckets.push(m);
        return {
          ...d,
          buckets: buckets.filter((b) => b.n > 0),
          counts: { ...d.counts, [m.e]: Math.max(0, (d.counts[m.e] || 0) + m.n) },
          total: Math.max(0, d.total + m.n),
        };
      });
    },
    [setMoments]
  );

  const chapters = useMemo(() => (video ? parseChapters(video.description, video.duration) : []), [video?.description, video?.duration]); // eslint-disable-line react-hooks/exhaustive-deps
  const startParam = parseTime(params.get("t"));

  useEffect(() => {
    if (video) document.title = `${video.title} · ${BRAND.name}`;
    return () => (document.title = BRAND.name);
  }, [video]);

  // Next video: next in playlist, otherwise first related
  let next = null;
  if (playlist?.videos?.length) {
    const i = playlist.videos.findIndex((v) => v._id === videoId);
    const n = playlist.videos[i + 1];
    if (n) next = { ...n, href: `/watch/${n._id}?list=${playlist._id}` };
  } else if (related?.length) {
    next = { ...related[0], href: `/watch/${related[0]._id}` };
  }

  const onFirstPlay = useCallback(() => {
    api.post(`/videos/${videoId}/view`).then(({ data }) => setVideo((v) => (v ? { ...v, views: data.data.views } : v))).catch(() => {});
  }, [videoId, setVideo]);

  const onProgress = useCallback(
    (position, duration) => {
      if (!user || !duration || !isFinite(duration)) return;
      api.post(`/videos/${videoId}/progress`, { position, duration }).catch(() => {});
    },
    [videoId, user]
  );

  const react = guard(async (type) => {
    const prev = video;
    // optimistic update
    setVideo((v) => {
      const was = v.myReaction;
      const now = was === type ? null : type;
      return {
        ...v,
        myReaction: now,
        likesCount: v.likesCount + (now === "like" ? 1 : 0) - (was === "like" ? 1 : 0),
        dislikesCount: v.dislikesCount + (now === "dislike" ? 1 : 0) - (was === "dislike" ? 1 : 0),
      };
    });
    try {
      const { data } = await api.post(`/likes/video/${videoId}`, { type });
      setVideo((v) => ({ ...v, ...data.data }));
    } catch (err) {
      setVideo(prev);
      toast.error(errMsg(err));
    }
  });


  if (loading && !video) return <PageSpinner />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!video) return null;

  const player = (
    <VideoPlayer
      ref={playerRef}
      key={videoId}
      src={mediaUrl(video.videoFile)}
      poster={mediaUrl(video.thumbnail)}
      startAt={Number.isFinite(startParam) ? startParam : video.progress}
      moments={moments?.buckets}
      chapters={chapters}
      showMoments={showMoments}
      onFirstPlay={onFirstPlay}
      onProgress={onProgress}
      theater={theater}
      onToggleTheater={() => setTheater((t) => (setPref("kn.theater", !t), !t))}
      nextVideo={autoplay && next ? { title: next.title, poster: mediaUrl(next.thumbnail) } : null}
      onNext={() => next && navigate(next.href)}
    />
  );

  const upNext = (
    <aside className="w-full lg:w-[400px] lg:shrink-0">
      {playlist && <PlaylistPanel playlist={playlist} currentId={videoId} />}
      <div className="mb-2 flex items-center justify-between">
        <h3 className="font-display font-semibold">Watch next</h3>
        <Toggle checked={autoplay} onChange={(v) => (setAutoplay(v), setPref("kn.autoplay", v))} label={<span className="text-xs text-zinc-400">Autoplay</span>} />
      </div>
      <button className="btn-ghost mb-3 w-full" onClick={() => shuffle(null, videoId)}>
        <GiPerspectiveDiceSixFacesRandom size={18} className="text-glow-soft" /> Shuffle something different
      </button>
      <div className="space-y-1">
        {related?.map((v) => <VideoListItem key={v._id} video={v} />)}
        {related?.length === 0 && <p className="text-sm text-zinc-500">No other videos yet.</p>}
      </div>
    </aside>
  );

  const owner = video.owner;

  return (
    // A single grid keeps the <VideoPlayer> mounted when switching theater mode (no playback restart)
    <div
      className={`grid grid-cols-1 lg:gap-x-6 [grid-template-areas:'player''info'] ${
        theater
          ? "lg:grid-cols-[minmax(0,1fr)_400px] lg:[grid-template-areas:'player_player''info_side']"
          : "mx-auto max-w-[1700px] sm:px-6 sm:pt-6 lg:grid-cols-[minmax(0,1fr)_400px] lg:[grid-template-areas:'player_side''info_side']"
      }`}
    >
      <div className={`[grid-area:player] ${theater ? "bg-black" : ""}`}>{player}</div>
      <div className={`hidden [grid-area:side] lg:block ${theater ? "pr-6 pt-6" : ""}`}>{upNext}</div>
      <div className={`min-w-0 [grid-area:info] ${theater ? "lg:pl-6" : ""}`}>
        <div>
          <div className={theater ? "px-4 sm:px-6 lg:px-0" : "px-4 sm:px-0"}>
            {!video.isPublished && (
              <p className="mt-3 rounded-lg bg-amber-500/15 px-3 py-2 text-sm text-amber-300">This video is a draft — only you can see it.</p>
            )}
            <h1 className="mt-4 text-xl font-bold leading-snug">{video.title}</h1>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <div className="flex min-w-0 items-center gap-3">
                <Avatar user={owner} size="h-10 w-10" link />
                <div className="min-w-0">
                  <Link to={`/c/${owner.username}`} className="block truncate font-semibold hover:underline">{owner.fullName}</Link>
                  <p className="text-xs text-zinc-400">{compact(owner.subscribersCount)} followers</p>
                </div>
                <SubscribeButton channel={owner} onChange={(d) => setVideo((v) => ({ ...v, owner: { ...v.owner, ...d } }))} />
                {video.isOwner && (
                  <Link to="/studio" className="btn-ghost"><MdOutlineEdit /> Edit in Studio</Link>
                )}
              </div>
              <div className="no-scrollbar flex items-center gap-2 overflow-x-auto sm:ml-auto">
                <div className="flex shrink-0 items-center overflow-hidden rounded-full bg-white/10">
                  <button onClick={() => react("like")} className="flex items-center gap-2 py-2 pl-4 pr-3 text-sm font-semibold hover:bg-white/10" title="Love this">
                    {video.myReaction === "like" ? <RiHeart3Fill size={20} className="text-pink-400" /> : <RiHeart3Line size={20} />} {compact(video.likesCount)}
                  </button>
                  <span className="h-6 w-px bg-white/20" />
                  <button onClick={() => react("dislike")} className="flex items-center gap-2 py-2 pl-3 pr-4 text-sm hover:bg-white/10" title="Not for me">
                    {video.myReaction === "dislike" ? <BiSolidDislike size={20} /> : <BiDislike size={20} />}
                    {video.dislikesCount > 0 && <span className="text-xs text-zinc-400">{compact(video.dislikesCount)}</span>}
                  </button>
                </div>
                <button className="btn-ghost shrink-0" onClick={() => setShareOpen(true)}><RiShareForwardLine size={18} /> Share</button>
                <button className="btn-ghost shrink-0" onClick={guard(() => setSaveOpen(true))}><MdPlaylistAdd size={20} /> Save</button>
                <div className="shrink-0"><MyListButton videoId={videoId} /></div>
              </div>
            </div>
            <MomentsBar
              data={moments}
              onAdd={addMoment}
              getTime={getTime}
              enabled={showMoments}
              onToggle={(v) => (setShowMoments(v), setPref("kn.moments", v))}
            />
            <ChapterStrip chapters={chapters} getTime={getTime} onSeek={seekTo} />
            <Description video={video} onSeek={seekTo} />
            <div className="lg:hidden mt-6">{upNext}</div>
            <div className="mt-8 flex gap-1 border-b border-ink-700">
              {[["comments", "Comments"], ["notes", "My notes"]].map(([k, label]) => (
                <button
                  key={k}
                  onClick={() => setTab(k)}
                  className={`-mb-px border-b-2 px-4 pb-3 text-sm font-semibold transition ${tab === k ? "border-brand text-white" : "border-transparent text-zinc-400 hover:text-white"}`}
                >
                  {label}
                </button>
              ))}
            </div>
            {tab === "comments" ? (
              <Comments key={videoId} videoId={videoId} videoOwnerId={owner._id} count={video.commentsCount} />
            ) : (
              <NotesPanel key={videoId} videoId={videoId} getTime={getTime} onSeek={seekTo} />
            )}
            <p className="hidden pb-8 text-xs text-zinc-600 lg:block">
              Shortcuts: Space/K play · J/L ±10s · ←/→ ±5s · ↑/↓ volume · M mute · F fullscreen · T theater · I mini-player · N next · S shuffle · Shift+&lt;/&gt; speed · 0–9 jump
            </p>
          </div>
        </div>
      </div>
      {user && <SaveToPlaylist videoId={videoId} open={saveOpen} onClose={() => setSaveOpen(false)} />}
      <ShareModal open={shareOpen} onClose={() => setShareOpen(false)} videoId={videoId} title={video.title} getTime={getTime} />
    </div>
  );
}
