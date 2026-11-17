import { useState } from "react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import { MdOutlineEdit, MdDeleteOutline, MdOutlineVisibility, MdThumbUpOffAlt, MdOutlineComment, MdPeopleOutline, MdOutlineVideoLibrary, MdAccessTime } from "react-icons/md";
import { RiVideoAddLine } from "react-icons/ri";
import { api, errMsg, mediaUrl } from "../api/client";
import { useFetch, useUser } from "../hooks";
import { compact, fullDate, longDuration } from "../utils/format";
import { Confirm, Empty, ErrorState, Modal, PageSpinner, Spinner, Toggle } from "../components/ui";

function Stat({ icon: Icon, label, value, sub }) {
  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 text-sm text-zinc-400"><Icon size={18} /> {label}</div>
      <p className="mt-2 text-2xl font-bold tabular-nums">{value}</p>
      {sub && <p className="text-xs text-emerald-400">{sub}</p>}
    </div>
  );
}

function EditVideo({ video, onClose, onSaved }) {
  const { data: categories } = useFetch("/videos/categories");
  const [form, setForm] = useState({
    title: video.title,
    description: video.description || "",
    category: video.category,
    tags: (video.tags || []).join(", "),
  });
  const [thumb, setThumb] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setForm((s) => ({ ...s, [k]: e.target.value }));

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    const fd = new FormData();
    Object.entries(form).forEach(([k, v]) => fd.append(k, v));
    if (thumb) fd.append("thumbnail", thumb);
    try {
      const { data } = await api.patch(`/videos/${video._id}`, fd);
      toast.success("Video updated");
      onSaved(data.data);
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open onClose={onClose} title="Edit video" width="max-w-2xl">
      <form onSubmit={save} className="space-y-4">
        <div className="flex flex-col gap-4 sm:flex-row">
          <label className="relative block aspect-video w-full shrink-0 cursor-pointer overflow-hidden rounded-lg bg-ink-800 sm:w-56">
            <img src={thumb ? URL.createObjectURL(thumb) : mediaUrl(video.thumbnail)} alt="" className="h-full w-full object-cover" />
            <span className="absolute inset-x-0 bottom-0 bg-black/70 py-1 text-center text-xs">Change thumbnail</span>
            <input type="file" accept="image/*" hidden onChange={(e) => setThumb(e.target.files[0] || null)} />
          </label>
          <div className="flex-1 space-y-3">
            <div>
              <label className="label">Title</label>
              <input className="input" value={form.title} onChange={set("title")} maxLength={120} required />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Category</label>
                <select className="input" value={form.category} onChange={set("category")}>
                  {(categories || [form.category]).map((c) => <option key={c}>{c}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Tags</label>
                <input className="input" value={form.tags} onChange={set("tags")} />
              </div>
            </div>
          </div>
        </div>
        <div>
          <label className="label">Description</label>
          <textarea className="input min-h-32" value={form.description} onChange={set("description")} maxLength={5000} />
        </div>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={busy}>{busy && <Spinner className="h-4 w-4" />} Save</button>
        </div>
      </form>
    </Modal>
  );
}

export default function Studio() {
  const user = useUser();
  const stats = useFetch("/dashboard/stats");
  const { data: videos, setData, loading, error, reload } = useFetch("/dashboard/videos");
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");

  const togglePublish = async (v) => {
    setData((list) => list.map((x) => (x._id === v._id ? { ...x, isPublished: !x.isPublished } : x)));
    try {
      const { data } = await api.patch(`/videos/${v._id}/publish`);
      toast.success(data.message);
      stats.reload();
    } catch (err) {
      toast.error(errMsg(err));
      reload();
    }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await api.delete(`/videos/${deleting._id}`);
      setData((list) => list.filter((x) => x._id !== deleting._id));
      toast.success("Video deleted");
      setDeleting(null);
      stats.reload();
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const s = stats.data;
  const shown = (videos || []).filter((v) => v.title.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="page">
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <div className="mr-auto">
          <h1 className="font-display text-3xl font-bold">Studio</h1>
          <p className="text-sm text-zinc-400">Welcome back, {user.fullName}</p>
        </div>
        <Link to={`/c/${user.username}`} className="btn-ghost">View channel</Link>
        <Link to="/upload" className="btn-primary"><RiVideoAddLine /> Upload</Link>
      </div>

      {s && (
        <div className="mb-8 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          <Stat icon={MdOutlineVisibility} label="Total views" value={compact(s.totalViews)} />
          <Stat icon={MdPeopleOutline} label="Followers" value={compact(s.totalSubscribers)} sub={s.newSubscribers30d ? `+${s.newSubscribers30d} last 30 days` : null} />
          <Stat icon={MdThumbUpOffAlt} label="Likes" value={compact(s.totalLikes)} />
          <Stat icon={MdOutlineComment} label="Comments" value={compact(s.totalComments)} />
          <Stat icon={MdOutlineVideoLibrary} label="Videos" value={s.totalVideos} sub={`${s.publishedVideos} published`} />
          <Stat icon={MdAccessTime} label="Content length" value={longDuration(s.totalDuration)} />
        </div>
      )}

      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 border-b border-ink-700 p-4">
          <h2 className="mr-auto font-semibold">Your videos</h2>
          <input className="input w-full sm:w-64" placeholder="Filter by title…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
        {loading ? (
          <PageSpinner />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : !videos.length ? (
          <Empty icon={MdOutlineVideoLibrary} title="No videos yet" action={<Link to="/upload" className="btn-primary">Upload your first video</Link>} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[800px] text-sm">
              <thead className="text-left text-xs uppercase tracking-wider text-zinc-500">
                <tr className="border-b border-ink-700">
                  <th className="p-3 pl-4">Video</th>
                  <th className="p-3">Visibility</th>
                  <th className="p-3 text-right">Views</th>
                  <th className="p-3 text-right">Likes</th>
                  <th className="p-3 text-right">Comments</th>
                  <th className="p-3">Date</th>
                  <th className="p-3" />
                </tr>
              </thead>
              <tbody>
                {shown.map((v) => (
                  <tr key={v._id} className="border-b border-ink-800 hover:bg-white/[0.02]">
                    <td className="p-3 pl-4">
                      <Link to={`/watch/${v._id}`} className="flex items-center gap-3">
                        <img src={mediaUrl(v.thumbnail)} alt="" className="aspect-video w-28 shrink-0 rounded object-cover" />
                        <div className="min-w-0">
                          <p className="line-clamp-1 font-semibold">{v.title}</p>
                          <p className="line-clamp-1 text-xs text-zinc-500">{v.category} · {v.description || "No description"}</p>
                        </div>
                      </Link>
                    </td>
                    <td className="p-3"><Toggle checked={v.isPublished} onChange={() => togglePublish(v)} label={<span className="text-xs">{v.isPublished ? "Public" : "Draft"}</span>} /></td>
                    <td className="p-3 text-right tabular-nums">{v.views.toLocaleString()}</td>
                    <td className="p-3 text-right tabular-nums">{v.likesCount}{v.dislikesCount > 0 && <span className="text-zinc-500"> / -{v.dislikesCount}</span>}</td>
                    <td className="p-3 text-right tabular-nums">{v.commentsCount}</td>
                    <td className="p-3 text-zinc-400">{fullDate(v.createdAt)}</td>
                    <td className="p-3">
                      <div className="flex justify-end gap-1">
                        <button className="btn-icon h-9 w-9" title="Edit" onClick={() => setEditing(v)}><MdOutlineEdit size={18} /></button>
                        <button className="btn-icon h-9 w-9 hover:text-brand-soft" title="Delete" onClick={() => setDeleting(v)}><MdDeleteOutline size={18} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <EditVideo
          video={editing}
          onClose={() => setEditing(null)}
          onSaved={(updated) => {
            setData((list) => list.map((x) => (x._id === updated._id ? { ...x, ...updated } : x)));
            setEditing(null);
          }}
        />
      )}
      <Confirm
        open={Boolean(deleting)}
        onClose={() => setDeleting(null)}
        onConfirm={remove}
        busy={busy}
        title="Delete video?"
        text={`“${deleting?.title}” and all its comments and likes will be permanently deleted.`}
      />
    </div>
  );
}
