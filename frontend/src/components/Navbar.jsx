import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useDispatch } from "react-redux";
import toast from "react-hot-toast";
import { HiOutlineMenu, HiOutlineSearch, HiArrowLeft } from "react-icons/hi";
import { RiVideoAddLine } from "react-icons/ri";
import { IoClose } from "react-icons/io5";
import { GiPerspectiveDiceSixFacesRandom } from "react-icons/gi";
import { MdOutlineDashboard, MdOutlineSettings, MdLogout, MdOutlineVideoLibrary } from "react-icons/md";
import { logout, toggleSidebar } from "../store";
import { useShuffle, useUser } from "../hooks";
import { BRAND } from "../brand";
import { Avatar } from "./ui";

export function Logo() {
  return (
    <Link to="/" className="flex items-center gap-2.5 font-display text-xl font-bold tracking-tight">
      <img src="/logo.svg" alt="" className="h-8 w-8 drop-shadow-[0_0_12px_rgba(139,92,246,0.45)]" />
      <span className="hidden sm:inline">{BRAND.name}</span>
    </Link>
  );
}

const RECENT_KEY = "kn.recentSearches";
const loadRecent = () => {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY)) || [];
  } catch {
    return [];
  }
};

function SearchBox({ onDone, autoFocus }) {
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const [focused, setFocused] = useState(false);
  const [recent, setRecent] = useState(loadRecent);
  const navigate = useNavigate();
  const inputRef = useRef(null);

  useEffect(() => {
    setQ(params.get("q") || "");
  }, [params]);

  // "/" focuses search, like popular video sites
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "/" && !/input|textarea/i.test(document.activeElement?.tagName)) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const go = (term) => {
    const t = term.trim();
    if (!t) return;
    const next = [t, ...recent.filter((r) => r.toLowerCase() !== t.toLowerCase())].slice(0, 8);
    setRecent(next);
    try {
      localStorage.setItem(RECENT_KEY, JSON.stringify(next));
    } catch {}
    setFocused(false);
    inputRef.current?.blur();
    navigate(`/search?q=${encodeURIComponent(t)}`);
    onDone?.();
  };

  const showRecent = focused && !q && recent.length > 0;

  return (
    <form className="relative flex w-full" onSubmit={(e) => (e.preventDefault(), go(q))}>
      <input
        ref={inputRef}
        autoFocus={autoFocus}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setTimeout(() => setFocused(false), 150)}
        placeholder="Search videos, channels, tags…"
        className="w-full rounded-l-xl border border-ink-600 bg-ink-900/80 px-4 py-2 text-sm outline-none transition focus:border-brand focus:bg-ink-900"
      />
      {q && (
        <button type="button" className="absolute right-16 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white" onClick={() => setQ("")}>
          <IoClose size={18} />
        </button>
      )}
      <button className="rounded-r-xl border border-l-0 border-ink-600 bg-ink-800 px-4 hover:bg-ink-700" aria-label="Search">
        <HiOutlineSearch size={20} />
      </button>
      {showRecent && (
        <div className="absolute left-0 right-12 top-full z-50 mt-1 overflow-hidden rounded-xl border border-ink-700 bg-ink-900 py-2 shadow-2xl animate-fadeIn">
          <div className="flex items-center justify-between px-4 pb-1 text-xs text-zinc-500">
            Recent searches
            <button type="button" className="hover:text-white" onMouseDown={() => (localStorage.removeItem(RECENT_KEY), setRecent([]))}>
              Clear
            </button>
          </div>
          {recent.map((r) => (
            <button type="button" key={r} onMouseDown={() => go(r)} className="flex w-full items-center gap-3 px-4 py-2 text-left text-sm hover:bg-white/5">
              <HiOutlineSearch className="text-zinc-500" /> {r}
            </button>
          ))}
        </div>
      )}
    </form>
  );
}

function UserMenu({ user }) {
  const [open, setOpen] = useState(false);
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const ref = useRef(null);

  useEffect(() => {
    const close = (e) => !ref.current?.contains(e.target) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const item = "flex w-full items-center gap-3 px-4 py-2.5 text-sm hover:bg-white/5";
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen((o) => !o)} className="rounded-full ring-brand transition hover:ring-2">
        <Avatar user={user} size="h-9 w-9" />
      </button>
      {open && (
        <div className="absolute right-0 top-12 z-50 w-64 overflow-hidden rounded-xl border border-ink-700 bg-ink-900 py-2 shadow-2xl animate-fadeIn" onClick={() => setOpen(false)}>
          <div className="flex items-center gap-3 border-b border-ink-700 px-4 pb-3">
            <Avatar user={user} size="h-10 w-10" />
            <div className="min-w-0">
              <p className="truncate font-semibold">{user.fullName}</p>
              <p className="truncate text-sm text-zinc-400">@{user.username}</p>
            </div>
          </div>
          <Link to={`/c/${user.username}`} className={item}><MdOutlineVideoLibrary size={20} /> Your channel</Link>
          <Link to="/studio" className={item}><MdOutlineDashboard size={20} /> Studio</Link>
          <Link to="/settings" className={item}><MdOutlineSettings size={20} /> Settings</Link>
          <button
            className={`${item} text-brand-soft`}
            onClick={async () => {
              await dispatch(logout());
              toast.success("Signed out");
              navigate("/");
            }}
          >
            <MdLogout size={20} /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export default function Navbar() {
  const user = useUser();
  const dispatch = useDispatch();
  const [mobileSearch, setMobileSearch] = useState(false);
  const shuffle = useShuffle();

  // "S" shuffles from anywhere (ignored while typing)
  useEffect(() => {
    const onKey = (e) => {
      if (e.key.toLowerCase() !== "s" || e.metaKey || e.ctrlKey || e.altKey) return;
      if (/input|textarea|select/i.test(document.activeElement?.tagName)) return;
      shuffle();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [shuffle]);

  if (mobileSearch) {
    return (
      <header className="sticky top-0 z-40 flex h-16 items-center gap-2 border-b border-ink-800 bg-ink-950/95 px-3 backdrop-blur">
        <button className="btn-icon" onClick={() => setMobileSearch(false)} aria-label="Back"><HiArrowLeft size={22} /></button>
        <SearchBox autoFocus onDone={() => setMobileSearch(false)} />
      </header>
    );
  }

  return (
    <header className="sticky top-0 z-40 flex h-16 items-center justify-between gap-4 border-b border-ink-800 bg-ink-950/90 px-3 backdrop-blur sm:px-4">
      <div className="flex items-center gap-2">
        <button className="btn-icon" onClick={() => dispatch(toggleSidebar())} aria-label="Menu">
          <HiOutlineMenu size={22} />
        </button>
        <Logo />
      </div>
      <div className="hidden max-w-xl flex-1 md:flex">
        <SearchBox />
      </div>
      <div className="flex items-center gap-1 sm:gap-2">
        <button className="btn-icon md:hidden" onClick={() => setMobileSearch(true)} aria-label="Search"><HiOutlineSearch size={22} /></button>
        <button className="btn-icon text-glow-soft" onClick={() => shuffle()} title="Shuffle: play something random (S)" aria-label="Shuffle">
          <GiPerspectiveDiceSixFacesRandom size={24} />
        </button>
        {user ? (
          <>
            <Link to="/upload" className="btn-ghost hidden sm:inline-flex"><RiVideoAddLine size={18} /> Upload</Link>
            <Link to="/upload" className="btn-icon sm:hidden" aria-label="Upload"><RiVideoAddLine size={22} /></Link>
            <UserMenu user={user} />
          </>
        ) : (
          <>
            <Link to="/login" className="btn-ghost">Sign in</Link>
            <Link to="/register" className="btn-primary hidden sm:inline-flex">Get started</Link>
          </>
        )}
      </div>
    </header>
  );
}
