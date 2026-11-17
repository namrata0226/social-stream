import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import { TbNotes } from "react-icons/tb";
import { MdDeleteOutline } from "react-icons/md";
import { HiOutlineSearch } from "react-icons/hi";
import { api, errMsg, mediaUrl } from "../api/client";
import { useFetch } from "../hooks";
import { duration as fmt, timeAgo } from "../utils/format";
import { Empty, ErrorState, PageSpinner } from "../components/ui";

/** Every private note the user has written, grouped by video. Each timestamp jumps into the video. */
export default function Notes() {
  const { data, setData, loading, error, reload } = useFetch("/notes");
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    if (!data) return [];
    const term = q.trim().toLowerCase();
    if (!term) return data;
    return data
      .map((g) => ({
        ...g,
        notes: g.video.title.toLowerCase().includes(term) ? g.notes : g.notes.filter((n) => n.text.toLowerCase().includes(term)),
      }))
      .filter((g) => g.notes.length);
  }, [data, q]);

  const remove = async (videoId, noteId) => {
    const prev = data;
    setData((groups) =>
      groups
        .map((g) => (g.video._id === videoId ? { ...g, notes: g.notes.filter((n) => n._id !== noteId) } : g))
        .filter((g) => g.notes.length)
    );
    try {
      await api.delete(`/notes/${noteId}`);
    } catch (err) {
      setData(prev);
      toast.error(errMsg(err));
    }
  };

  if (loading && !data) return <PageSpinner />;
  if (error) return <ErrorState message={error} onRetry={reload} />;

  const total = data?.reduce((n, g) => n + g.notes.length, 0) || 0;

  return (
    <div className="page max-w-5xl">
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-tight">My Notes</h1>
          <p className="mt-1 text-sm text-zinc-400">
            {total ? `${total} note${total === 1 ? "" : "s"} across ${data.length} video${data.length === 1 ? "" : "s"} · private to you` : "Private, timestamped notes you take while watching."}
          </p>
        </div>
        {total > 0 && (
          <label className="relative w-full sm:w-72">
            <HiOutlineSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input className="input pl-9" placeholder="Search your notes" value={q} onChange={(e) => setQ(e.target.value)} />
          </label>
        )}
      </div>

      {!total ? (
        <Empty
          icon={TbNotes}
          title="No notes yet"
          text="Open any video, switch to the My notes tab, and write something down. Each note remembers the second you wrote it."
          action={<Link to="/explore" className="btn-primary">Find something to watch</Link>}
        />
      ) : !filtered.length ? (
        <Empty icon={HiOutlineSearch} title="No matches" text={`Nothing in your notes matches “${q}”.`} />
      ) : (
        <div className="space-y-5">
          {filtered.map(({ video, notes, lastEdited }) => (
            <section key={video._id} className="card flex flex-col gap-4 p-4 sm:flex-row">
              <Link to={`/watch/${video._id}`} className="shrink-0 sm:w-56">
                <img src={mediaUrl(video.thumbnail)} alt="" className="aspect-video w-full rounded-xl object-cover" />
                <p className="mt-2 line-clamp-2 text-sm font-semibold leading-snug">{video.title}</p>
                <p className="text-xs text-zinc-500">{video.owner?.fullName} · edited {timeAgo(lastEdited)}</p>
              </Link>
              <ul className="min-w-0 flex-1 space-y-1">
                {notes.map((n) => (
                  <li key={n._id} className="group flex gap-3 rounded-xl p-2 hover:bg-white/[0.03]">
                    <Link
                      to={`/watch/${video._id}?t=${Math.floor(n.time)}`}
                      className="h-fit shrink-0 rounded-lg bg-brand/15 px-2 py-1 text-xs font-bold tabular-nums text-brand-soft hover:bg-brand/25"
                    >
                      {fmt(n.time)}
                    </Link>
                    <p className="min-w-0 flex-1 whitespace-pre-wrap break-words text-sm text-zinc-200">{n.text}</p>
                    <button className="btn-icon h-8 w-8 shrink-0 opacity-0 group-hover:opacity-100" onClick={() => remove(video._id, n._id)} aria-label="Delete note">
                      <MdDeleteOutline size={16} />
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
