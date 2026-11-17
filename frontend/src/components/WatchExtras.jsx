import { useEffect, useRef, useState } from "react";
import toast from "react-hot-toast";
import { MdDeleteOutline, MdOutlineEdit, MdContentCopy } from "react-icons/md";
import { TbNotes } from "react-icons/tb";
import { api, errMsg } from "../api/client";
import { useAuthGuard, useFetch, useUser } from "../hooks";
import { compact, duration as fmt } from "../utils/format";
import { chapterAt } from "../utils/chapters";
import { Modal, Spinner, Toggle } from "./ui";

/* ---------------- Moments bar ---------------- */

const LABELS = { "🔥": "Fire", "😂": "Funny", "😮": "Whoa", "❤️": "Love it", "👏": "Applause", "🤯": "Mind-blown" };

/** Row of emoji that drop a reaction at the current second of the video. */
export function MomentsBar({ data, onAdd, getTime, enabled, onToggle }) {
  const guard = useAuthGuard();
  const [popped, setPopped] = useState(null);
  if (!data) return null;

  const drop = guard(async (emoji) => {
    setPopped(emoji + Date.now());
    const time = getTime();
    onAdd({ t: Math.floor(time), e: emoji, n: 1 }, true);
    try {
      await api.post(`/moments/video/${data.videoId}`, { emoji, time });
    } catch (err) {
      onAdd({ t: Math.floor(time), e: emoji, n: -1 }, false); // roll back
      toast.error(errMsg(err));
    }
  });

  // the hottest second, for the "Peak moment" hint
  const perSecond = new Map();
  for (const b of data.buckets) perSecond.set(b.t, (perSecond.get(b.t) || 0) + b.n);
  let peak = null;
  for (const [t, n] of perSecond) if (n > (peak?.n || 0)) peak = { t, n };

  return (
    <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-3 rounded-2xl border border-brand/20 bg-gradient-to-r from-brand/10 via-indigo-500/5 to-glow/10 px-4 py-3">
      <div className="min-w-0">
        <p className="font-display text-sm font-semibold">Drop a Moment</p>
        <p className="text-xs text-zinc-400">
          {data.total ? `${compact(data.total)} reactions on the timeline` : "React at the exact second something hits"}
          {peak?.n > 1 && <> · peak at <span className="font-semibold text-glow-soft">{fmt(peak.t)}</span></>}
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {data.emojis.map((e) => (
          <button
            key={e}
            onClick={() => drop(e)}
            title={`${LABELS[e] || e} at this moment`}
            className="group flex items-center gap-1.5 rounded-full bg-white/[0.06] px-2.5 py-1.5 ring-1 ring-inset ring-white/10 transition hover:-translate-y-0.5 hover:bg-white/[0.12] active:scale-95"
          >
            <span key={popped?.startsWith(e) ? popped : e} className={`text-lg leading-none ${popped?.startsWith(e) ? "animate-pop" : ""}`}>{e}</span>
            {data.counts[e] > 0 && <span className="text-xs tabular-nums text-zinc-300">{compact(data.counts[e])}</span>}
          </button>
        ))}
      </div>
      <div className="ml-auto">
        <Toggle checked={enabled} onChange={onToggle} label={<span className="text-xs text-zinc-400">Show on video</span>} />
      </div>
    </div>
  );
}

/* ---------------- Chapters ---------------- */

export function ChapterStrip({ chapters, getTime, onSeek }) {
  const [time, setTime] = useState(0);
  // poll instead of lifting player time into the page, so the page doesn't re-render 4x a second
  useEffect(() => {
    if (!chapters.length) return;
    const id = setInterval(() => setTime(getTime()), 1000);
    return () => clearInterval(id);
  }, [chapters.length, getTime]);
  if (!chapters.length) return null;
  const current = chapterAt(chapters, time);
  return (
    <div className="mt-4">
      <p className="mb-2 text-sm font-semibold">Chapters</p>
      <div className="no-scrollbar flex gap-2 overflow-x-auto pb-1">
        {chapters.map((c, i) => {
          const active = current?.start === c.start;
          return (
            <button
              key={c.start}
              onClick={() => onSeek(c.start)}
              className={`w-44 shrink-0 rounded-xl p-2.5 text-left transition ${active ? "bg-brand/20 ring-1 ring-brand/50" : "bg-ink-800 hover:bg-ink-700"}`}
            >
              <span className="text-[11px] font-semibold text-glow-soft">{i + 1} · {fmt(c.start)}</span>
              <span className="mt-0.5 line-clamp-2 block text-sm font-medium leading-snug">{c.title}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ---------------- Notes ---------------- */

function NoteItem({ note, onSeek, onChange, onDelete }) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(note.text);
  const save = async () => {
    if (!text.trim() || text === note.text) return setEditing(false);
    try {
      const { data } = await api.patch(`/notes/${note._id}`, { text });
      onChange(data.data);
      setEditing(false);
    } catch (err) {
      toast.error(errMsg(err));
    }
  };
  return (
    <li className="group flex gap-3 rounded-xl p-2 hover:bg-white/[0.03]">
      <button onClick={() => onSeek(note.time)} className="h-fit shrink-0 rounded-lg bg-brand/15 px-2 py-1 text-xs font-bold tabular-nums text-brand-soft hover:bg-brand/25" title="Jump to this moment">
        {fmt(note.time)}
      </button>
      <div className="min-w-0 flex-1">
        {editing ? (
          <textarea
            className="input min-h-16 py-2"
            value={text}
            autoFocus
            maxLength={1000}
            onChange={(e) => setText(e.target.value)}
            onBlur={save}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) (e.preventDefault(), save());
              if (e.key === "Escape") (setText(note.text), setEditing(false));
            }}
          />
        ) : (
          <p className="whitespace-pre-wrap break-words text-sm text-zinc-200">{note.text}</p>
        )}
      </div>
      {!editing && (
        <div className="flex shrink-0 opacity-0 transition group-hover:opacity-100">
          <button className="btn-icon h-8 w-8" onClick={() => setEditing(true)} aria-label="Edit note"><MdOutlineEdit size={16} /></button>
          <button className="btn-icon h-8 w-8" onClick={() => onDelete(note._id)} aria-label="Delete note"><MdDeleteOutline size={16} /></button>
        </div>
      )}
    </li>
  );
}

/** Private, timestamped notes for the signed-in viewer. Great for tutorials and lectures. */
export function NotesPanel({ videoId, getTime, onSeek }) {
  const user = useUser();
  const guard = useAuthGuard();
  const { data: notes, setData, loading } = useFetch(user ? `/notes/video/${videoId}` : null);
  const [text, setText] = useState("");
  const [at, setAt] = useState(null);
  const [busy, setBusy] = useState(false);

  const capture = () => at === null && setAt(getTime());

  const add = guard(async (e) => {
    e?.preventDefault();
    if (!text.trim()) return;
    setBusy(true);
    try {
      const { data } = await api.post(`/notes/video/${videoId}`, { text, time: at ?? getTime() });
      setData((list) => [...(list || []), data.data].sort((a, b) => a.time - b.time));
      setText("");
      setAt(null);
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  });

  const remove = async (id) => {
    const prev = notes;
    setData((l) => l.filter((n) => n._id !== id));
    try {
      await api.delete(`/notes/${id}`);
    } catch (err) {
      setData(prev);
      toast.error(errMsg(err));
    }
  };

  return (
    <div className="py-6">
      <form onSubmit={add} className="card p-3">
        <textarea
          className="w-full resize-none bg-transparent text-sm outline-none placeholder:text-zinc-500"
          rows={2}
          maxLength={1000}
          placeholder={user ? "Write a private note — it's pinned to this moment in the video…" : "Sign in to keep private notes on videos"}
          value={text}
          onFocus={guard(capture)}
          onChange={(e) => (setText(e.target.value), capture())}
          onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && add(e)}
        />
        <div className="mt-2 flex items-center gap-2">
          <span className="rounded-lg bg-white/[0.06] px-2 py-1 text-xs tabular-nums text-zinc-300">at {fmt(at ?? 0)}</span>
          {at !== null && (
            <button type="button" className="text-xs text-zinc-400 hover:text-white" onClick={() => setAt(getTime())}>use current time</button>
          )}
          <span className="ml-auto text-[11px] text-zinc-500">Only you can see your notes</span>
          <button className="btn-primary py-1.5" disabled={busy || !text.trim()}>{busy && <Spinner className="h-3 w-3" />} Save note</button>
        </div>
      </form>

      {loading ? (
        <div className="flex justify-center py-8"><Spinner /></div>
      ) : notes?.length ? (
        <ul className="mt-4 space-y-1">
          {notes.map((n) => (
            <NoteItem key={n._id} note={n} onSeek={onSeek} onDelete={remove} onChange={(nn) => setData((l) => l.map((x) => (x._id === nn._id ? nn : x)))} />
          ))}
        </ul>
      ) : user ? (
        <div className="flex flex-col items-center py-10 text-center text-sm text-zinc-500">
          <TbNotes size={28} className="mb-2" />
          No notes yet. Notes are saved with a timestamp, so you can jump straight back.
        </div>
      ) : null}
    </div>
  );
}

/* ---------------- Share ---------------- */

export function ShareModal({ open, onClose, videoId, title, getTime }) {
  const [atTime, setAtTime] = useState(false);
  const t = useRef(0);
  useEffect(() => {
    if (open) {
      t.current = Math.floor(getTime());
      setAtTime(t.current > 3);
    }
  }, [open, getTime]);

  const url = `${window.location.origin}/watch/${videoId}${atTime && t.current ? `?t=${t.current}` : ""}`;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(url);
      toast.success("Link copied");
      onClose();
    } catch {
      toast.error("Couldn't copy — select the link instead");
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Share" width="max-w-md">
      <div className="flex gap-2">
        <input readOnly className="input" value={url} onFocus={(e) => e.target.select()} />
        <button className="btn-primary shrink-0" onClick={copy}><MdContentCopy /> Copy</button>
      </div>
      {t.current > 0 && (
        <div className="mt-4">
          <Toggle checked={atTime} onChange={setAtTime} label={<span>Start at <b className="tabular-nums">{fmt(t.current)}</b></span>} />
        </div>
      )}
      {navigator.share && (
        <button className="btn-ghost mt-4 w-full" onClick={() => navigator.share({ title, url }).then(onClose).catch(() => {})}>
          More options…
        </button>
      )}
    </Modal>
  );
}
