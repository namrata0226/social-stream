import { useState } from "react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import { BiLike, BiSolidLike } from "react-icons/bi";
import { HiDotsVertical, HiChevronDown, HiChevronUp } from "react-icons/hi";
import { MdSort } from "react-icons/md";
import { api, errMsg } from "../api/client";
import { useAuthGuard, useInView, usePaged, useUser } from "../hooks";
import { compact, timeAgo } from "../utils/format";
import { Avatar, Spinner } from "./ui";

function CommentForm({ onSubmit, placeholder = "Add a comment…", autoFocus, initial = "", onCancel, submitLabel = "Comment", small }) {
  const user = useUser();
  const guard = useAuthGuard();
  const [text, setText] = useState(initial);
  const [focused, setFocused] = useState(Boolean(autoFocus));
  const [busy, setBusy] = useState(false);

  const submit = guard(async (e) => {
    e?.preventDefault();
    if (!text.trim()) return;
    setBusy(true);
    try {
      await onSubmit(text.trim());
      setText("");
      setFocused(false);
      onCancel?.();
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  });

  return (
    <form onSubmit={submit} className="flex gap-3">
      {user && <Avatar user={user} size={small ? "h-7 w-7" : "h-10 w-10"} />}
      <div className="flex-1">
        <textarea
          rows={1}
          value={text}
          autoFocus={autoFocus}
          onFocus={guard(() => setFocused(true))}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && (e.metaKey || e.ctrlKey) && submit()}
          placeholder={placeholder}
          maxLength={2000}
          className="w-full resize-none border-b border-ink-600 bg-transparent py-1.5 text-sm outline-none transition focus:border-white [field-sizing:content]"
        />
        {focused && (
          <div className="mt-2 flex justify-end gap-2">
            <button type="button" className="btn-ghost py-1.5" onClick={() => (setFocused(false), setText(initial), onCancel?.())}>Cancel</button>
            <button className="btn-primary py-1.5" disabled={!text.trim() || busy}>{busy && <Spinner className="h-3 w-3" />} {submitLabel}</button>
          </div>
        )}
      </div>
    </form>
  );
}

function Comment({ comment, videoId, videoOwnerId, onDeleted, onReplyAdded, isReply }) {
  const user = useUser();
  const guard = useAuthGuard();
  const [c, setC] = useState(comment);
  const [editing, setEditing] = useState(false);
  const [replying, setReplying] = useState(false);
  const [menu, setMenu] = useState(false);
  const [showReplies, setShowReplies] = useState(false);
  const [replies, setReplies] = useState(null);

  const isAuthor = user && c.owner?._id === user._id;
  const canDelete = isAuthor || (user && user._id === videoOwnerId);

  const like = guard(async () => {
    setC((x) => ({ ...x, isLiked: !x.isLiked, likesCount: x.likesCount + (x.isLiked ? -1 : 1) }));
    try {
      const { data } = await api.post(`/likes/comment/${c._id}`);
      setC((x) => ({ ...x, ...data.data }));
    } catch (err) {
      toast.error(errMsg(err));
    }
  });

  const loadReplies = async () => {
    if (showReplies) return setShowReplies(false);
    setShowReplies(true);
    if (!replies) {
      const { data } = await api.get(`/comments/${c._id}/replies`);
      setReplies(data.data.docs);
    }
  };

  const remove = async () => {
    try {
      await api.delete(`/comments/${c._id}`);
      toast.success("Comment deleted");
      onDeleted(c._id, 1 + (c.replyCount || 0));
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  const addReply = async (text) => {
    const { data } = await api.post(`/comments/video/${videoId}`, { content: text, parentId: c._id });
    if (isReply) return onReplyAdded?.(data.data);
    setReplies((r) => [...(r || []), data.data]);
    setShowReplies(true);
    setC((x) => ({ ...x, replyCount: (x.replyCount || 0) + 1 }));
    onReplyAdded?.();
  };

  return (
    <div className="flex gap-3 animate-fadeIn">
      <Avatar user={c.owner} size={isReply ? "h-7 w-7" : "h-10 w-10"} link />
      <div className="min-w-0 flex-1">
        {editing ? (
          <CommentForm
            initial={c.content}
            autoFocus
            submitLabel="Save"
            onCancel={() => setEditing(false)}
            onSubmit={async (text) => {
              const { data } = await api.patch(`/comments/${c._id}`, { content: text });
              setC((x) => ({ ...x, content: data.data.content, edited: true }));
            }}
          />
        ) : (
          <>
            <p className="text-xs">
              <Link to={`/c/${c.owner?.username}`} className="font-semibold hover:underline">@{c.owner?.username}</Link>
              <span className="ml-2 text-zinc-500">{timeAgo(c.createdAt)}{c.edited && " (edited)"}</span>
            </p>
            <p className="mt-1 whitespace-pre-wrap break-words text-sm">{c.content}</p>
            <div className="mt-1 flex items-center gap-1 text-xs">
              <button onClick={like} className="btn-icon h-8 w-8">{c.isLiked ? <BiSolidLike size={16} className="text-brand-soft" /> : <BiLike size={16} />}</button>
              <span className="min-w-4 text-zinc-400">{c.likesCount > 0 && compact(c.likesCount)}</span>
              <button className="ml-2 rounded-full px-3 py-1.5 font-semibold hover:bg-white/10" onClick={guard(() => setReplying(true))}>Reply</button>
              {(isAuthor || canDelete) && (
                <div className="relative ml-auto">
                  <button className="btn-icon h-8 w-8" onClick={() => setMenu((m) => !m)} aria-label="Comment options"><HiDotsVertical /></button>
                  {menu && (
                    <div className="absolute right-0 z-10 w-28 overflow-hidden rounded-lg border border-ink-700 bg-ink-900 py-1 text-sm shadow-xl" onMouseLeave={() => setMenu(false)}>
                      {isAuthor && <button className="block w-full px-3 py-2 text-left hover:bg-white/5" onClick={() => (setEditing(true), setMenu(false))}>Edit</button>}
                      {canDelete && <button className="block w-full px-3 py-2 text-left text-brand-soft hover:bg-white/5" onClick={remove}>Delete</button>}
                    </div>
                  )}
                </div>
              )}
            </div>
          </>
        )}
        {replying && (
          <div className="mt-2">
            <CommentForm small autoFocus placeholder={`Reply to @${c.owner?.username}…`} submitLabel="Reply" onSubmit={addReply} onCancel={() => setReplying(false)} />
          </div>
        )}
        {!isReply && c.replyCount > 0 && (
          <button onClick={loadReplies} className="mt-1 flex items-center gap-1 rounded-full px-3 py-1.5 text-sm font-semibold text-sky-400 hover:bg-sky-400/10">
            {showReplies ? <HiChevronUp /> : <HiChevronDown />} {c.replyCount} {c.replyCount === 1 ? "reply" : "replies"}
          </button>
        )}
        {showReplies && (
          <div className="mt-2 space-y-4">
            {!replies && <Spinner className="h-4 w-4" />}
            {replies?.map((r) => (
              <Comment
                key={r._id}
                comment={r}
                videoId={videoId}
                videoOwnerId={videoOwnerId}
                isReply
                onDeleted={(id) => {
                  setReplies((list) => list.filter((x) => x._id !== id));
                  setC((x) => ({ ...x, replyCount: x.replyCount - 1 }));
                  onDeleted(null, 1);
                }}
                onReplyAdded={(reply) => {
                  setReplies((list) => [...list, reply]);
                  setC((x) => ({ ...x, replyCount: x.replyCount + 1 }));
                  onReplyAdded?.();
                }}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function Comments({ videoId, videoOwnerId, count: initialCount }) {
  const [sort, setSort] = useState("newest");
  const [count, setCount] = useState(initialCount || 0);
  const { items, setItems, loading, hasMore, loadMore } = usePaged(`/comments/video/${videoId}`, { sort }, 20);
  const sentinel = useInView(loadMore, hasMore && !loading);

  return (
    <section className="mt-6">
      <div className="mb-6 flex items-center gap-6">
        <h2 className="text-xl font-bold">{compact(count)} Comments</h2>
        <button className="flex items-center gap-2 text-sm font-semibold" onClick={() => setSort((s) => (s === "newest" ? "top" : "newest"))}>
          <MdSort size={22} /> {sort === "top" ? "Top comments" : "Newest first"}
        </button>
      </div>
      <CommentForm
        onSubmit={async (text) => {
          const { data } = await api.post(`/comments/video/${videoId}`, { content: text });
          setItems((list) => [data.data, ...list]);
          setCount((n) => n + 1);
        }}
      />
      <div className="mt-6 space-y-6">
        {items.map((c) => (
          <Comment
            key={c._id}
            comment={c}
            videoId={videoId}
            videoOwnerId={videoOwnerId}
            onDeleted={(id, n) => {
              if (id) setItems((list) => list.filter((x) => x._id !== id));
              setCount((x) => Math.max(0, x - n));
            }}
            onReplyAdded={() => setCount((n) => n + 1)}
          />
        ))}
      </div>
      <div ref={sentinel} className="flex justify-center py-6">{loading && <Spinner />}</div>
    </section>
  );
}
