import { BRAND } from "../brand";
import { useSearchParams } from "react-router-dom";
import { HiOutlineSearch } from "react-icons/hi";
import { useFetch, useInView, usePaged } from "../hooks";
import { VideoListItem } from "../components/VideoCard";
import { Empty, ErrorState, PageSpinner, Spinner } from "../components/ui";

export default function Search() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") || "";
  const sort = params.get("sort") || "";
  const category = params.get("category") || "All";
  const { data: categories } = useFetch("/videos/categories");
  const query = { q, category, ...(sort ? { sort } : {}) };
  const { items, loading, error, hasMore, loadMore, reload } = usePaged(q ? "/videos" : null, query, 20);
  const sentinel = useInView(loadMore, hasMore && !loading);

  const set = (k, v) => {
    const next = new URLSearchParams(params);
    v ? next.set(k, v) : next.delete(k);
    setParams(next, { replace: true });
  };

  if (!q) return <Empty icon={HiOutlineSearch} title={`Search ${BRAND.name}`} text="Find videos by title, description, tag or channel." />;

  return (
    <div className="page max-w-6xl">
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h1 className="mr-auto text-xl font-bold">Results for “{q}”</h1>
        <select value={category} onChange={(e) => set("category", e.target.value === "All" ? "" : e.target.value)} className="input w-auto py-1.5">
          {["All", ...(categories || [])].map((c) => <option key={c}>{c}</option>)}
        </select>
        <select value={sort} onChange={(e) => set("sort", e.target.value)} className="input w-auto py-1.5">
          <option value="">Relevance</option>
          <option value="latest">Upload date</option>
          <option value="popular">View count</option>
          <option value="duration">Length</option>
        </select>
      </div>
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !items.length ? (
        <PageSpinner />
      ) : !items.length ? (
        <Empty icon={HiOutlineSearch} title="No results" text="Try different keywords or remove filters." />
      ) : (
        <div className="space-y-3">
          {items.map((v) => <VideoListItem key={v._id} video={v} large />)}
          <div ref={sentinel} className="flex justify-center py-8">{loading && <Spinner />}</div>
        </div>
      )}
    </div>
  );
}
