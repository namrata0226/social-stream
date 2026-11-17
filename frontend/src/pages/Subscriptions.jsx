import { Link } from "react-router-dom";
import { RiUserHeartLine } from "react-icons/ri";
import { useFetch, useInView, usePaged } from "../hooks";
import { VideoGrid } from "../components/VideoCard";
import { Avatar, Empty, GridSkeleton, Spinner } from "../components/ui";
import { compact } from "../utils/format";

export default function Subscriptions() {
  const { data: channels } = useFetch("/subscriptions/channels");
  const { items, loading, hasMore, loadMore } = usePaged("/subscriptions/feed", {}, 24);
  const sentinel = useInView(loadMore, hasMore && !loading);

  if (channels && !channels.length) {
    return (
      <Empty
        icon={RiUserHeartLine}
        title="You're not following anyone yet"
        text="Follow creators you love and their latest uploads will land here."
        action={<Link to="/explore" className="btn-primary">Discover creators</Link>}
      />
    );
  }

  return (
    <div className="page">
      {channels?.length > 0 && (
        <div className="no-scrollbar mb-8 flex gap-5 overflow-x-auto pb-2">
          {channels.map((c) => (
            <Link key={c._id} to={`/c/${c.username}`} className="flex w-20 shrink-0 flex-col items-center gap-2 text-center">
              <span className="rounded-full bg-aurora p-[2px]"><Avatar user={c} size="h-16 w-16" className="ring-2 ring-ink-950" /></span>
              <span className="line-clamp-1 text-xs">{c.fullName}</span>
              <span className="-mt-2 text-[10px] text-zinc-500">{compact(c.subscribersCount)} followers</span>
            </Link>
          ))}
        </div>
      )}
      <h1 className="page-title">New from people you follow</h1>
      {loading && !items.length ? <GridSkeleton /> : !items.length ? (
        <Empty title="No videos yet" text="Channels you follow haven't uploaded anything yet." />
      ) : (
        <>
          <VideoGrid videos={items} />
          <div ref={sentinel} className="flex justify-center py-8">{loading && <Spinner />}</div>
        </>
      )}
    </div>
  );
}
