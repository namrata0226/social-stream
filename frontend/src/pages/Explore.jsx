import { useSearchParams } from "react-router-dom";
import { MdOutlineExplore } from "react-icons/md";
import { useFetch, useInView, usePaged } from "../hooks";
import { VideoGrid } from "../components/VideoCard";
import { Empty, ErrorState, GridSkeleton, Spinner } from "../components/ui";

const SORTS = [
  ["latest", "Latest"],
  ["popular", "Popular"],
  ["oldest", "Oldest"],
  ["duration", "Longest"],
];

export default function Explore() {
  const [params, setParams] = useSearchParams();
  const category = params.get("category") || "All";
  const sort = params.get("sort") || "latest";
  const { data: categories } = useFetch("/videos/categories");
  const { items, loading, error, hasMore, loadMore, reload } = usePaged("/videos", { category, sort });
  const sentinel = useInView(loadMore, hasMore && !loading);

  const set = (k, v) => {
    const next = new URLSearchParams(params);
    next.set(k, v);
    setParams(next, { replace: true });
  };

  return (
    <div className="page">
      <div className="sticky top-16 z-20 -mx-4 mb-6 flex flex-col gap-3 bg-ink-950/95 px-4 py-3 backdrop-blur sm:-mx-6 sm:px-6 md:flex-row md:items-center">
        <div className="no-scrollbar flex flex-1 gap-2 overflow-x-auto">
          {["All", ...(categories || [])].map((c) => (
            <button key={c} onClick={() => set("category", c)} className={`chip ${c === category ? "bg-white text-black" : "bg-ink-800 hover:bg-ink-700"}`}>
              {c}
            </button>
          ))}
        </div>
        <select value={sort} onChange={(e) => set("sort", e.target.value)} className="input w-auto py-1.5">
          {SORTS.map(([v, l]) => <option key={v} value={v}>Sort: {l}</option>)}
        </select>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : items.length === 0 && loading ? (
        <GridSkeleton />
      ) : items.length === 0 ? (
        <Empty icon={MdOutlineExplore} title="Nothing here yet" text={`No videos in ${category} yet.`} />
      ) : (
        <>
          <VideoGrid videos={items} />
          <div ref={sentinel} className="flex justify-center py-10">{loading && <Spinner />}</div>
        </>
      )}
    </div>
  );
}
