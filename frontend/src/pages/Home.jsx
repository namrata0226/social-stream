import { Link } from "react-router-dom";
import { MdVideoLibrary } from "react-icons/md";
import { useFetch, useUser } from "../hooks";
import Hero from "../components/Hero";
import MoodPicker from "../components/MoodPicker";
import VideoRow from "../components/VideoRow";
import { Empty, ErrorState, PageSpinner } from "../components/ui";

const ROW_LINKS = {
  trending: "/explore?sort=popular",
  new: "/explore?sort=latest",
  popular: "/explore?sort=popular",
  subscriptions: "/following",
  mylist: "/watchlist",
  continue: "/history",
};

export default function Home() {
  const user = useUser();
  // refetch when the user signs in/out so personal rows appear
  const { data, loading, error, reload } = useFetch("/videos/browse", { deps: [user?._id] });

  if (loading && !data) return <PageSpinner />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data?.rows.length) {
    return (
      <Empty
        icon={MdVideoLibrary}
        title="No videos yet"
        text="Be the first to share something with the community."
        action={<Link to="/upload" className="btn-primary">Upload a video</Link>}
      />
    );
  }

  return (
    <div className="pb-16">
      <Hero items={data.featured} />
      <div className="mt-8 space-y-8">
        <MoodPicker />
        {data.rows.map((row) => (
          <VideoRow
            key={row.key}
            title={row.title}
            videos={row.videos}
            ranked={row.key === "trending"}
            link={row.category ? `/explore?category=${encodeURIComponent(row.category)}` : ROW_LINKS[row.key]}
          />
        ))}
      </div>
    </div>
  );
}
