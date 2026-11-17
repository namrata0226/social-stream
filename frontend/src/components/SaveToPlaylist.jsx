import { useState } from "react";
import toast from "react-hot-toast";
import { HiPlus, HiLockClosed } from "react-icons/hi";
import { api, errMsg } from "../api/client";
import { useFetch, useUser } from "../hooks";
import { Modal, Spinner, Toggle } from "./ui";

export default function SaveToPlaylist({ videoId, open, onClose }) {
  const user = useUser();
  const { data, loading, setData } = useFetch(open && user ? `/playlists/user/${user._id}` : null, { params: { videoId } });
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [isPublic, setIsPublic] = useState(true);

  const toggle = async (p) => {
    try {
      const { data: res } = await api.post(`/playlists/${p._id}/videos/${videoId}`);
      setData((list) => list.map((x) => (x._id === p._id ? { ...x, hasVideo: res.data.hasVideo } : x)));
      toast.success(res.message);
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  const create = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      const { data: res } = await api.post("/playlists", { name, isPublic, videoId });
      setData((list) => [{ ...res.data, hasVideo: true }, ...(list || [])]);
      toast.success(`Saved to ${res.data.name}`);
      setName("");
      setCreating(false);
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Save to playlist" width="max-w-sm">
      {loading ? (
        <div className="py-6 text-center"><Spinner /></div>
      ) : (
        <div className="max-h-64 space-y-1 overflow-y-auto">
          {data?.length === 0 && <p className="py-2 text-sm text-zinc-400">You have no playlists yet.</p>}
          {data?.map((p) => (
            <label key={p._id} className="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-2 hover:bg-white/5">
              <input type="checkbox" checked={Boolean(p.hasVideo)} onChange={() => toggle(p)} className="h-4 w-4 accent-brand" />
              <span className="flex-1 truncate text-sm">{p.name}</span>
              {!p.isPublic && <HiLockClosed className="text-zinc-500" />}
            </label>
          ))}
        </div>
      )}
      {creating ? (
        <form onSubmit={create} className="mt-4 space-y-3 border-t border-ink-700 pt-4">
          <input autoFocus className="input" placeholder="Playlist name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          <Toggle checked={isPublic} onChange={setIsPublic} label={isPublic ? "Public" : "Private"} />
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-ghost" onClick={() => setCreating(false)}>Cancel</button>
            <button className="btn-primary" disabled={!name.trim()}>Create</button>
          </div>
        </form>
      ) : (
        <button className="btn-ghost mt-4 w-full" onClick={() => setCreating(true)}><HiPlus /> New playlist</button>
      )}
    </Modal>
  );
}
