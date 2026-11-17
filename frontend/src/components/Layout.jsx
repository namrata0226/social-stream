import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import Navbar from "./Navbar";
import Sidebar from "./Sidebar";
import { setSidebar } from "../store";

export default function Layout() {
  const { pathname } = useLocation();
  const open = useSelector((s) => s.ui.sidebarOpen);
  const dispatch = useDispatch();
  // Watch page uses an overlay drawer so the player gets full width
  const overlayOnly = pathname.startsWith("/watch");

  useEffect(() => {
    if (overlayOnly || window.innerWidth < 1024) dispatch(setSidebar(false));
  }, [pathname, overlayOnly, dispatch]);

  return (
    <div className="min-h-screen">
      <Navbar />
      <Sidebar overlayOnly={overlayOnly} />
      <main className={`transition-[padding] duration-200 ${overlayOnly ? "" : open ? "lg:pl-60" : "lg:pl-[72px]"}`}>
        <Outlet />
      </main>
    </div>
  );
}
