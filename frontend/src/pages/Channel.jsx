import { useState } from "react";
import { Link, NavLink, useParams } from "react-router-dom";
import toast from "react-hot-toast";
import { BiLike, BiSolidLike } from "react-icons/bi";
import { MdOutlineVideoLibrary, MdPlaylistPlay, MdOutlineForum } from "react-icons/md";
import { HiLockClosed } from "react-icons/hi";
import { api, errMsg, mediaUrl } from "../api/client";
import { useAuthGuard, useFetch, useInView, usePaged, useUser } from "../hooks";
import { compact, fullDate, timeAgo } from "../utils/format";
import { VideoGrid } from "../components/VideoCard";
import { Avatar, Confirm, Empty, ErrorState, GridSkeleton, PageSpinner, Spinner } from "../components/ui";
import { SubscribeButton } from "./Watch";

function Videos({ channel }) {
  const [sort, setSort] = useState("latest");
  const params = { owner: channel._id, sort, includeDrafts: channel.isOwner ? "true" : undefined };
  const { items, loading, hasMore, loadMore } = usePaged("/videos", params, 24);
  const sentinel = useInView(loadMore, hasMore && !loading);

  return (
    <>
      <div className="mb-5 flex gap-2">
        {[["latest", "Latest"], ["popular", "Popular"], ["oldest", "Oldest"]].map(([v, l]) => (
          <button key={v} onClick={() => setSort(v)} className={`chip ${sort === v ? "bg-white text-black" : "bg-ink-800 hover:bg-ink-700"}`}>{l}</button>
        ))}
      </div>
      {loading && !items.length ? (
        <GridSkeleton />
      ) : !items.length ? (
        <Empty
          icon={MdOutlineVideoLibrary}
          title="No videos yet"
          text={channel.isOwner ? "Upload your first video to get started." : "This channel hasn't uploaded anything yet."}
          action={channel.isOwner && <Link to="/upload" className="btn-primary">Upload video</Link>}
        />
      ) : (
        <>
          <VideoGrid videos={items} />
          <div ref={sentinel} className="flex justify-center py-8">{loading && <Spinner />}</div>
        </>
      )}
    </>
  );
}

export function PlaylistCard({ p }) {
  return (
    <Link to={`/playlist/${p._id}`} className="group block">
      <div className="relative aspect-video overflow-hidden rounded-xl bg-ink-800">
        {p.thumbnail && <img src={mediaUrl(p.thumbnail)} alt="" className="h-full w-full object-cover transition group-hover:scale-105" />}
        <div className="absolute inset-y-0 right-0 flex w-2/5 flex-col items-center justify-center bg-black/75 text-sm font-semibold">
          <MdPlaylistPlay size={28} /> {p.videosCount} videos
        </div>
      </div>
      <p className="mt-2 flex items-center gap-2 font-semibold">{p.name} {!p.isPublic && <HiLockClosed className="text-zinc-500" />}</p>
      <p className="text-sm text-zinc-400">Updated {timeAgo(p.updatedAt)}</p>
    </Link>
  );
}

function Playlists({ channel }) {
  const { data, loading } = useFetch(`/playlists/user/${channel._id}`);
  if (loading) return <PageSpinner />;
  if (!data?.length) return <Empty icon={MdPlaylistPlay} title="No playlists" text={channel.isOwner ? "Use “Save” on any video to create a playlist." : "This channel has no public playlists."} />;
  return (
    <div className="grid gap-x-4 gap-y-8 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {data.map((p) => <PlaylistCard key={p._id} p={p} />)}
    </div>
  );
}

function Post({ post, isOwner, onDelete, onUpdate }) {
  const guard = useAuthGuard();
  const [p, setP] = useState(post);
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(post.content);
  const [confirm, setConfirm] = useState(false);

  const like = guard(async () => {
    setP((x) => ({ ...x, isLiked: !x.isLiked, likesCount: x.likesCount + (x.isLiked ? -1 : 1) }));
    const { data } = await api.post(`/likes/post/${p._id}`);
    setP((x) => ({ ...x, ...data.data }));
  });

  const save = async () => {
    try {
      const { data } = await api.patch(`/posts/${p._id}`, { content: text });
      setP((x) => ({ ...x, content: data.data.content }));
      setEditing(false);
      onUpdate?.();
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  return (
    <div className="card p-4 animate-fadeIn">
      <div className="flex items-center gap-3">
        <Avatar user={p.owner} />
        <div>
          <p className="text-sm font-semibold">{p.owner?.fullName}</p>
          <p className="text-xs text-zinc-500">{timeAgo(p.createdAt)}</p>
        </div>
        {isOwner && !editing && (
          <div className="ml-auto flex gap-1 text-xs">
            <button className="rounded-full px-3 py-1 hover:bg-white/10" onClick={() => setEditing(true)}>Edit</button>
            <button className="rounded-full px-3 py-1 text-brand-soft hover:bg-white/10" onClick={() => setConfirm(true)}>Delete</button>
          </div>
        )}
      </div>
      {editing ? (
        <div className="mt-3">
          <textarea className="input min-h-24" value={text} onChange={(e) => setText(e.target.value)} />
          <div className="mt-2 flex justify-end gap-2">
            <button className="btn-ghost" onClick={() => (setEditing(false), setText(p.content))}>Cancel</button>
            <button className="btn-primary" onClick={save} disabled={!text.trim()}>Save</button>
          </div>
        </div>
      ) : (
        <p className="mt-3 whitespace-pre-wrap break-words text-sm">{p.content}</p>
      )}
      <button onClick={like} className="mt-3 flex items-center gap-2 rounded-full px-2 py-1 text-sm hover:bg-white/10">
        {p.isLiked ? <BiSolidLike className="text-brand-soft" size={18} /> : <BiLike size={18} />} {compact(p.likesCount)}
      </button>
      <Confirm
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Delete post?"
        text="This can't be undone."
        onConfirm={async () => {
          await api.delete(`/posts/${p._id}`);
          toast.success("Post deleted");
          onDelete(p._id);
        }}
      />
    </div>
  );
}

function Community({ channel }) {
  const { data, loading, setData } = useFetch(`/posts/user/${channel._id}`);
  const user = useUser();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);

  const create = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      const { data: res } = await api.post("/posts", { content: text });
      setData((list) => [{ ...res.data, owner: user, likesCount: 0, isLiked: false }, ...(list || [])]);
      setText("");
      toast.success("Posted");
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-3xl space-y-4">
      {channel.isOwner && (
        <form onSubmit={create} className="card p-4">
          <textarea className="input min-h-24" placeholder="Share an update with your followers…" value={text} onChange={(e) => setText(e.target.value)} maxLength={2000} />
          <div className="mt-2 flex items-center justify-end gap-3">
            <span className="text-xs text-zinc-500">{text.length}/2000</span>
            <button className="btn-primary" disabled={!text.trim() || busy}>Post</button>
          </div>
        </form>
      )}
      {loading ? <PageSpinner /> : !data?.length ? (
        <Empty icon={MdOutlineForum} title="No posts yet" text="Community posts from this channel will show up here." />
      ) : (
        data.map((p) => <Post key={p._id} post={p} isOwner={channel.isOwner} onDelete={(id) => setData((l) => l.filter((x) => x._id !== id))} />)
      )}
    </div>
  );
}

function About({ channel }) {
  const { data: subs } = useFetch(`/subscriptions/c/${channel._id}/subscribers`);
  return (
    <div className="grid max-w-5xl gap-8 md:grid-cols-[1fr_280px]">
      <div>
        <h3 className="mb-2 font-semibold">Description</h3>
        <p className="whitespace-pre-wrap text-sm text-zinc-300">{channel.bio || "No description yet."}</p>
        {subs?.length > 0 && (
          <>
            <h3 className="mb-3 mt-8 font-semibold">Followers</h3>
            <div className="flex flex-wrap gap-3">
              {subs.map((s) => (
                <Link key={s._id} to={`/c/${s.username}`} className="flex items-center gap-2 rounded-full bg-ink-800 py-1 pl-1 pr-3 text-sm hover:bg-ink-700">
                  <Avatar user={s} size="h-7 w-7" /> {s.fullName}
                </Link>
              ))}
            </div>
          </>
        )}
      </div>
      <div className="card h-fit space-y-3 p-4 text-sm">
        <h3 className="font-semibold">Stats</h3>
        <p className="border-t border-ink-700 pt-3">Joined {fullDate(channel.createdAt)}</p>
        <p className="border-t border-ink-700 pt-3">{channel.totalViews.toLocaleString()} views</p>
        <p className="border-t border-ink-700 pt-3">{channel.subscribersCount.toLocaleString()} followers</p>
        <p className="border-t border-ink-700 pt-3">Following {channel.subscribedToCount} creators</p>
      </div>
    </div>
  );
}

const TABS = [
  ["", "Videos", Videos],
  ["playlists", "Playlists", Playlists],
  ["community", "Community", Community],
  ["about", "About", About],
];

export default function Channel() {
  const { username, "*": tab = "" } = useParams();
  const { data: channel, setData, loading, error, reload } = useFetch(`/users/c/${username}`);

  if (loading && !channel) return <PageSpinner />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!channel) return null;
  const Active = (TABS.find(([k]) => k === tab) || TABS[0])[2];

  return (
    <div>
      <div className="relative h-32 bg-gradient-to-br from-brand/50 via-indigo-600/30 to-glow/30 sm:h-48 lg:h-60">
        {channel.coverImage?.url && <img src={mediaUrl(channel.coverImage)} alt="" className="h-full w-full object-cover" />}
      </div>
      <div className="page pt-0">
        <div className="-mt-10 flex flex-col gap-4 sm:-mt-12 sm:flex-row sm:items-end">
          <Avatar user={channel} size="h-24 w-24 sm:h-32 sm:w-32" className="border-4 border-ink-950 text-4xl shadow-xl shadow-brand/20" />
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold sm:text-3xl">{channel.fullName}</h1>
            <p className="mt-1 text-sm text-zinc-400">
              @{channel.username} · {compact(channel.subscribersCount)} followers · {channel.videosCount} videos
            </p>
            {channel.bio && <p className="mt-1 line-clamp-1 text-sm text-zinc-400">{channel.bio}</p>}
          </div>
          <div className="flex gap-2">
            {channel.isOwner ? (
              <>
                <Link to="/settings" className="btn-ghost">Customize channel</Link>
                <Link to="/studio" className="btn-ghost">Manage videos</Link>
              </>
            ) : (
              <SubscribeButton channel={channel} onChange={(d) => setData((c) => ({ ...c, ...d }))} />
            )}
          </div>
        </div>
        <nav className="no-scrollbar mt-6 flex gap-6 overflow-x-auto border-b border-ink-700">
          {TABS.map(([k, label]) => (
            <NavLink
              key={k}
              to={`/c/${username}${k ? `/${k}` : ""}`}
              end
              className={({ isActive }) => `whitespace-nowrap border-b-2 pb-3 text-sm font-semibold transition ${isActive ? "border-brand text-white" : "border-transparent text-zinc-400 hover:text-white"}`}
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="pt-6">
          <Active channel={channel} />
        </div>
      </div>
    </div>
  );
}
