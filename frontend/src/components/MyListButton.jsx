import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { HiOutlineBookmark, HiBookmark } from "react-icons/hi";
import { api, errMsg } from "../api/client";
import { useAuthGuard, useUser } from "../hooks";
import { useDispatch } from "react-redux";
import { patchUser } from "../store";

/** Add/remove a video from the user's Watchlist. Membership is read from the user in the store. */
export default function MyListButton({ videoId, compact, initial }) {
  const user = useUser();
  const dispatch = useDispatch();
  const guard = useAuthGuard();
  const fromStore = Boolean(user?.myList?.some((id) => String(id) === String(videoId)));
  const [inList, setInList] = useState(initial ?? fromStore);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setInList(fromStore);
  }, [fromStore]);

  const toggle = guard(async (e) => {
    e?.stopPropagation();
    setBusy(true);
    try {
      const { data } = await api.post(`/users/my-list/${videoId}`);
      setInList(data.data.inMyList);
      const list = user.myList || [];
      dispatch(patchUser({ myList: data.data.inMyList ? [videoId, ...list] : list.filter((id) => String(id) !== String(videoId)) }));
      toast.success(data.message);
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  });

  const Icon = inList ? HiBookmark : HiOutlineBookmark;
  if (compact) {
    return (
      <button
        onClick={(e) => (e.stopPropagation(), toggle())}
        disabled={busy}
        title={inList ? "Remove from Watchlist" : "Add to Watchlist"}
        className={`flex h-8 w-8 items-center justify-center rounded-full border-2 bg-black/40 transition hover:border-white ${inList ? "border-glow text-glow" : "border-white/60 text-white"}`}
      >
        <Icon size={16} />
      </button>
    );
  }
  return (
    <button onClick={toggle} disabled={busy} className="btn-ghost">
      <Icon size={18} className={inList ? "text-glow" : ""} /> {inList ? "Saved" : "Watchlist"}
    </button>
  );
}
