import { useEffect } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { IoClose } from "react-icons/io5";
import { mediaUrl } from "../api/client";

export function Spinner({ className = "h-6 w-6" }) {
  return <span className={`inline-block animate-spin rounded-full border-2 border-white/20 border-t-brand ${className}`} />;
}

export function PageSpinner({ full }) {
  return (
    <div className={`flex items-center justify-center ${full ? "h-screen" : "py-24"}`}>
      <Spinner className="h-10 w-10" />
    </div>
  );
}

export function Avatar({ user, size = "h-9 w-9", link = false, className = "" }) {
  const src = mediaUrl(user?.avatar);
  const initials = (user?.fullName || user?.username || "?").slice(0, 1).toUpperCase();
  const img = src ? (
    <img src={src} alt={user?.username} className={`${size} shrink-0 rounded-full bg-ink-700 object-cover ${className}`} />
  ) : (
    <span className={`${size} inline-flex shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-brand to-glow font-semibold text-white ${className}`}>
      {initials}
    </span>
  );
  return link && user?.username ? <Link to={`/c/${user.username}`} onClick={(e) => e.stopPropagation()}>{img}</Link> : img;
}

export function Empty({ icon: Icon, title, text, action }) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-20 text-center animate-fadeIn">
      {Icon && (
        <div className="mb-4 rounded-full bg-ink-800 p-5 text-zinc-400">
          <Icon size={36} />
        </div>
      )}
      <h3 className="text-lg font-semibold">{title}</h3>
      {text && <p className="mt-1 max-w-sm text-sm text-zinc-400">{text}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }) {
  return (
    <Empty
      title="Something went wrong"
      text={message}
      action={onRetry && <button className="btn-ghost" onClick={onRetry}>Try again</button>}
    />
  );
}

export function Modal({ open, onClose, title, children, width = "max-w-lg" }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-fadeIn" onMouseDown={onClose}>
      <div className={`card w-full ${width} max-h-[90vh] overflow-y-auto p-5 animate-rise`} onMouseDown={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button className="btn-icon h-8 w-8" onClick={onClose} aria-label="Close">
            <IoClose size={20} />
          </button>
        </div>
        {children}
      </div>
    </div>,
    document.body
  );
}

export function Confirm({ open, onClose, onConfirm, title, text, confirmLabel = "Delete", busy }) {
  return (
    <Modal open={open} onClose={onClose} title={title} width="max-w-sm">
      <p className="text-sm text-zinc-400">{text}</p>
      <div className="mt-6 flex justify-end gap-2">
        <button className="btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn-primary" onClick={onConfirm} disabled={busy}>
          {busy && <Spinner className="h-4 w-4" />} {confirmLabel}
        </button>
      </div>
    </Modal>
  );
}

export function CardSkeleton() {
  return (
    <div className="animate-pulse">
      <div className="aspect-video rounded-xl bg-ink-800" />
      <div className="mt-3 flex gap-3">
        <div className="h-9 w-9 rounded-full bg-ink-800" />
        <div className="flex-1 space-y-2">
          <div className="h-4 w-11/12 rounded bg-ink-800" />
          <div className="h-3 w-2/3 rounded bg-ink-800" />
        </div>
      </div>
    </div>
  );
}

export function GridSkeleton({ count = 8 }) {
  return (
    <div className="grid gap-x-4 gap-y-8 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {Array.from({ length: count }, (_, i) => <CardSkeleton key={i} />)}
    </div>
  );
}

export function Toggle({ checked, onChange, label }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-3 text-sm">
      <span className={`relative h-6 w-11 rounded-full transition ${checked ? "bg-brand" : "bg-ink-600"}`}>
        <input type="checkbox" className="sr-only" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${checked ? "left-[22px]" : "left-0.5"}`} />
      </span>
      {label}
    </label>
  );
}
