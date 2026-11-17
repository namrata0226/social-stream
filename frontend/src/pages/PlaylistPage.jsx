import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import toast from "react-hot-toast";
import { FaPlay } from "react-icons/fa";
import { HiLockClosed, HiOutlineGlobe } from "react-icons/hi";
import { MdClose, MdDeleteOutline, MdOutlineEdit, MdShuffle } from "react-icons/md";
import { api, errMsg, mediaUrl } from "../api/client";
import { useFetch } from "../hooks";
import { VideoListItem } from "../components/VideoCard";
import { Avatar, Confirm, Empty, ErrorState, Modal, PageSpinner, Toggle } from "../components/ui";
import { longDuration, timeAgo, compact } from "../utils/format";

export default function PlaylistPage() {
  const { playlistId } = useParams();
  const navigate = useNavigate();
  const { data: p, setData, loading, error, reload } = useFetch(`/playlists/${playlistId}`);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [form, setForm] = useState(null);

  if (loading && !p) return <PageSpinner />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!p) return null;

  const first = p.videos[0];
  const shuffle = () => {
    const v = p.videos[Math.floor(Math.random() * p.videos.length)];
    navigate(`/watch/${v._id}?list=${p._id}`);
  };

  const removeVideo = async (videoId) => {
    try {
      await api.post(`/playlists/${p._id}/videos/${videoId}`);
      setData((x) => ({ ...x, videos: x.videos.filter((v) => v._id !== videoId) }));
      toast.success("Removed from playlist");
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  const save = async (e) => {
    e.preventDefault();
    try {
      const { data } = await api.patch(`/playlists/${p._id}`, form);
      setData((x) => ({ ...x, ...data.data, videos: x.videos, owner: x.owner }));
      setEditing(false);
      toast.success("Playlist updated");
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  return (
    <div className="page flex flex-col gap-8 lg:flex-row">
      <aside className="relative h-fit overflow-hidden rounded-2xl p-6 lg:sticky lg:top-24 lg:w-[360px] lg:shrink-0">
        {first && <img src={mediaUrl(first.thumbnail)} alt="" className="absolute inset-0 h-full w-full scale-150 object-cover opacity-40 blur-3xl" />}
        <div className="absolute inset-0 bg-gradient-to-b from-transparent to-ink-950/80" />
        <div className="relative">
          <div className="aspect-video overflow-hidden rounded-xl bg-ink-800">{first && <img src={mediaUrl(first.thumbnail)} alt="" className="h-full w-full object-cover" />}</div>
          <h1 className="mt-4 text-2xl font-bold">{p.name}</h1>
          <Link to={`/c/${p.owner?.username}`} className="mt-3 flex items-center gap-2 text-sm font-semibold"><Avatar user={p.owner} size="h-6 w-6" /> {p.owner?.fullName}</Link>
          <p className="mt-2 flex items-center gap-1 text-xs text-zinc-300">
            {p.isPublic ? <HiOutlineGlobe /> : <HiLockClosed />} {p.isPublic ? "Public" : "Private"} · {p.videos.length} videos · {compact(p.totalViews)} views · {longDuration(p.totalDuration)} · Updated {timeAgo(p.updatedAt)}
          </p>
          {p.description && <p className="mt-3 text-sm text-zinc-300">{p.description}</p>}
          {p.isOwner && (
            <div className="mt-4 flex gap-2">
              <button className="btn-icon bg-white/10" title="Edit" onClick={() => (setForm({ name: p.name, description: p.description, isPublic: p.isPublic }), setEditing(true))}><MdOutlineEdit /></button>
              <button className="btn-icon bg-white/10" title="Delete" onClick={() => setDeleting(true)}><MdDeleteOutline /></button>
            </div>
          )}
          {first && (
            <div className="mt-5 flex gap-2">
              <Link to={`/watch/${first._id}?list=${p._id}`} className="btn-light flex-1"><FaPlay /> Play all</Link>
              <button className="btn-ghost flex-1" onClick={shuffle}><MdShuffle size={18} /> Shuffle</button>
            </div>
          )}
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        {!p.videos.length ? (
          <Empty title="This playlist is empty" text="Use the Save button on any video to add it here." />
        ) : (
          <div className="space-y-1">
            {p.videos.map((v, i) => (
              <div key={v._id} className="group flex items-center">
                <div className="min-w-0 flex-1"><VideoListItem video={v} index={i} /></div>
                {p.isOwner && (
                  <button className="btn-icon opacity-0 group-hover:opacity-100" title="Remove" onClick={() => removeVideo(v._id)}><MdClose /></button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {editing && (
        <Modal open onClose={() => setEditing(false)} title="Edit playlist">
          <form onSubmit={save} className="space-y-4">
            <div><label className="label">Name</label><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></div>
            <div><label className="label">Description</label><textarea className="input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
            <Toggle checked={form.isPublic} onChange={(v) => setForm({ ...form, isPublic: v })} label={form.isPublic ? "Public" : "Private"} />
            <div className="flex justify-end gap-2"><button type="button" className="btn-ghost" onClick={() => setEditing(false)}>Cancel</button><button className="btn-primary">Save</button></div>
          </form>
        </Modal>
      )}
      <Confirm
        open={deleting}
        onClose={() => setDeleting(false)}
        title="Delete playlist?"
        text="The videos themselves won't be deleted."
        onConfirm={async () => {
          await api.delete(`/playlists/${p._id}`);
          toast.success("Playlist deleted");
          navigate(`/c/${p.owner.username}/playlists`);
        }}
      />
    </div>
  );
}
