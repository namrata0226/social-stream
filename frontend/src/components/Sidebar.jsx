import { NavLink } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { GoHome, GoHomeFill } from "react-icons/go";
import { MdOutlineExplore, MdExplore, MdHistory, MdOutlineDashboard, MdDashboard, MdOutlineSettings } from "react-icons/md";
import { HiOutlineBookmark, HiBookmark } from "react-icons/hi";
import { TbNotes } from "react-icons/tb";
import { RiHeart3Line, RiHeart3Fill, RiUserHeartLine, RiUserHeartFill } from "react-icons/ri";
import { RiVideoAddLine, RiVideoAddFill } from "react-icons/ri";
import { Logo } from "./Navbar";
import { setSidebar } from "../store";
import { useFetch, useUser } from "../hooks";
import { Avatar } from "./ui";
import { BRAND } from "../brand";
import { HiOutlineMenu } from "react-icons/hi";

const MAIN = [
  { to: "/", label: "Home", icon: GoHome, active: GoHomeFill, end: true },
  { to: "/explore", label: "Discover", icon: MdOutlineExplore, active: MdExplore },
  { to: "/following", label: "Following", icon: RiUserHeartLine, active: RiUserHeartFill },
];
const LIBRARY = [
  { to: "/watchlist", label: "Watchlist", icon: HiOutlineBookmark, active: HiBookmark },
  { to: "/notes", label: "My Notes", icon: TbNotes, active: TbNotes },
  { to: "/loved", label: "Loved", icon: RiHeart3Line, active: RiHeart3Fill },
  { to: "/history", label: "History", icon: MdHistory, active: MdHistory },
];
const CREATOR = [
  { to: "/upload", label: "Upload", icon: RiVideoAddLine, active: RiVideoAddFill },
  { to: "/studio", label: "Studio", icon: MdOutlineDashboard, active: MdDashboard },
  { to: "/settings", label: "Settings", icon: MdOutlineSettings, active: MdOutlineSettings },
];

function Item({ item, mini, onClick }) {
  return (
    <NavLink
      to={item.to}
      end={item.end}
      onClick={onClick}
      className={({ isActive }) =>
        `flex items-center rounded-xl transition ${mini ? "flex-col gap-1 px-1 py-3 text-[10px]" : "gap-4 px-3 py-2.5 text-sm"} ${
          isActive ? "bg-gradient-to-r from-brand/20 to-transparent font-semibold text-white ring-1 ring-inset ring-brand/20" : "text-zinc-300 hover:bg-white/5"
        }`
      }
    >
      {({ isActive }) => {
        const Icon = isActive ? item.active : item.icon;
        return (
          <>
            <Icon size={mini ? 22 : 21} className={isActive ? "text-brand" : ""} />
            <span className="truncate">{item.label}</span>
          </>
        );
      }}
    </NavLink>
  );
}

function Subscriptions({ onClick }) {
  const { data } = useFetch("/subscriptions/channels");
  if (!data?.length) return null;
  return (
    <Section title="Following">
      {data.slice(0, 8).map((c) => (
        <NavLink
          key={c._id}
          to={`/c/${c.username}`}
          onClick={onClick}
          className={({ isActive }) => `flex items-center gap-3 rounded-xl px-3 py-2 text-sm ${isActive ? "bg-white/10" : "text-zinc-300 hover:bg-white/5"}`}
        >
          <Avatar user={c} size="h-6 w-6" />
          <span className="truncate">{c.fullName}</span>
        </NavLink>
      ))}
    </Section>
  );
}

const Section = ({ title, children }) => (
  <div className="border-t border-ink-800 py-3">
    {title && <p className="px-3 pb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">{title}</p>}
    <div className="space-y-0.5">{children}</div>
  </div>
);

export default function Sidebar({ overlayOnly }) {
  const open = useSelector((s) => s.ui.sidebarOpen);
  const dispatch = useDispatch();
  const user = useUser();
  const close = () => window.innerWidth < 1024 || overlayOnly ? dispatch(setSidebar(false)) : null;

  const full = (
    <nav className="no-scrollbar h-full space-y-1 overflow-y-auto px-3 pb-8">
      <div className="space-y-0.5 py-2">{MAIN.map((i) => <Item key={i.to} item={i} onClick={close} />)}</div>
      {user ? (
        <>
          <Section title="Your space">{LIBRARY.map((i) => <Item key={i.to} item={i} onClick={close} />)}</Section>
          <Section title="Create">{CREATOR.map((i) => <Item key={i.to} item={i} onClick={close} />)}</Section>
          <Subscriptions onClick={close} />
        </>
      ) : (
        <Section>
          <p className="px-3 text-sm text-zinc-400">Sign in to drop Moments, keep notes, follow creators and build your watchlist.</p>
          <NavLink to="/login" onClick={close} className="btn-ghost mx-3 mt-3">Sign in</NavLink>
        </Section>
      )}
      <p className="px-3 pt-4 text-xs text-zinc-600">© {new Date().getFullYear()} {BRAND.name} · {BRAND.tagline}</p>
    </nav>
  );

  return (
    <>
      {/* Persistent rail / sidebar on large screens */}
      {!overlayOnly && (
        <aside className={`fixed bottom-0 left-0 top-16 z-30 hidden border-r border-white/[0.04] bg-ink-950/80 backdrop-blur lg:block ${open ? "w-60" : "w-[72px]"}`}>
          {open ? full : (
            <nav className="space-y-1 px-1 py-2">
              {[...MAIN, ...(user ? [LIBRARY[0], CREATOR[0]] : [])].map((i) => <Item key={i.to} item={i} mini />)}
            </nav>
          )}
        </aside>
      )}

      {/* Drawer for small screens and the watch page */}
      <div className={`fixed inset-0 z-50 ${overlayOnly ? "" : "lg:hidden"} ${open ? "" : "pointer-events-none"}`}>
        <div className={`absolute inset-0 bg-black/60 transition-opacity ${open ? "opacity-100" : "opacity-0"}`} onClick={() => dispatch(setSidebar(false))} />
        <aside className={`absolute bottom-0 left-0 top-0 w-64 bg-ink-950 shadow-2xl transition-transform ${open ? "translate-x-0" : "-translate-x-full"}`}>
          <div className="flex h-16 items-center gap-2 px-3">
            <button className="btn-icon" onClick={() => dispatch(setSidebar(false))} aria-label="Close menu"><HiOutlineMenu size={22} /></button>
            <Logo />
          </div>
          <div className="h-[calc(100%-4rem)]">{full}</div>
        </aside>
      </div>
    </>
  );
}
