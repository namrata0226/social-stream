import { useState } from "react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import { MdHistory, MdDeleteOutline, MdClose } from "react-icons/md";
import { RiHeart3Line } from "react-icons/ri";
import { HiOutlineBookmark } from "react-icons/hi";
import { api, errMsg } from "../api/client";
import { useFetch, useInView, usePaged } from "../hooks";
import { VideoGrid } from "../components/VideoCard";
import { Confirm, Empty, ErrorState, GridSkeleton, Spinner } from "../components/ui";
import { fullDate } from "../utils/format";

function History() {
  const { items, setItems, loading, error, hasMore, loadMore, reload } = usePaged("/users/history", {}, 24);
  const sentinel = useInView(loadMore, hasMore && !loading);
  const [confirm, setConfirm] = useState(false);

  const removeOne = async (videoId) => {
    try {
      await api.delete(`/users/history/${videoId}`);
      setItems((list) => list.filter((h) => h.video._id !== videoId));
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  const clear = async () => {
    await api.delete("/users/history");
    setItems([]);
    setConfirm(false);
    toast.success("Watch history cleared");
  };

  // group entries by day
  const groups = items.reduce((acc, h) => {
    const d = new Date(h.watchedAt);
    const today = new Date();
    const yest = new Date(Date.now() - 864e5);
    const label = d.toDateString() === today.toDateString() ? "Today" : d.toDateString() === yest.toDateString() ? "Yesterday" : fullDate(d);
    (acc[label] ||= []).push(h);
    return acc;
  }, {});

  return (
    <div className="page">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="font-display text-3xl font-bold">Watch history</h1>
        {items.length > 0 && <button className="btn-ghost" onClick={() => setConfirm(true)}><MdDeleteOutline size={18} /> Clear all</button>}
      </div>
      {error ? <ErrorState message={error} onRetry={reload} /> : loading && !items.length ? <GridSkeleton /> : !items.length ? (
        <Empty icon={MdHistory} title="No watch history" text="Videos you watch will show up here, and you can pick up where you left off." action={<Link to="/" className="btn-primary">Browse videos</Link>} />
      ) : (
        <div className="space-y-10">
          {Object.entries(groups).map(([label, list]) => (
            <section key={label}>
              <h2 className="mb-4 text-lg font-semibold">{label}</h2>
              <VideoGrid
                videos={list.map((h) => ({ ...h.video, progress: { position: h.position, duration: h.duration } }))}
                renderActions={(v) => (
                  <button className="btn-icon h-8 w-8 shrink-0" title="Remove from history" onClick={() => removeOne(v._id)}><MdClose size={18} /></button>
                )}
              />
            </section>
          ))}
          <div ref={sentinel} className="flex justify-center py-6">{loading && <Spinner />}</div>
        </div>
      )}
      <Confirm open={confirm} onClose={() => setConfirm(false)} onConfirm={clear} title="Clear watch history?" text="This also resets your “Pick up where you left off” row." confirmLabel="Clear" />
    </div>
  );
}

function SimpleList({ url, title, icon, emptyTitle, emptyText }) {
  const { data, loading, error, reload } = useFetch(url);
  return (
    <div className="page">
      <h1 className="page-title">{title} {data?.length > 0 && <span className="text-base font-normal text-zinc-500">· {data.length}</span>}</h1>
      {error ? <ErrorState message={error} onRetry={reload} /> : loading ? <GridSkeleton /> : !data.length ? (
        <Empty icon={icon} title={emptyTitle} text={emptyText} action={<Link to="/" className="btn-primary">Find something to watch</Link>} />
      ) : (
        <VideoGrid videos={data} />
      )}
    </div>
  );
}

export default function Library({ kind }) {
  if (kind === "history") return <History />;
  if (kind === "liked") return <SimpleList url="/likes/videos" title="Loved" icon={RiHeart3Line} emptyTitle="Nothing loved yet" emptyText="Tap ♥ on videos you enjoy and they'll collect here." />;
  return <SimpleList url="/users/my-list" title="Watchlist" icon={HiOutlineBookmark} emptyTitle="Your watchlist is empty" emptyText="Bookmark videos to come back to them later." />;
}
