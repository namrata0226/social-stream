import { lazy, Suspense, useEffect } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { Toaster } from "react-hot-toast";
import { fetchMe } from "./store";
import Layout from "./components/Layout";
import { PageSpinner } from "./components/ui";
import Home from "./pages/Home";

const Explore = lazy(() => import("./pages/Explore"));
const Search = lazy(() => import("./pages/Search"));
const Watch = lazy(() => import("./pages/Watch"));
const Channel = lazy(() => import("./pages/Channel"));
const Upload = lazy(() => import("./pages/Upload"));
const Studio = lazy(() => import("./pages/Studio"));
const Library = lazy(() => import("./pages/Library"));
const Subscriptions = lazy(() => import("./pages/Subscriptions"));
const PlaylistPage = lazy(() => import("./pages/PlaylistPage"));
const Notes = lazy(() => import("./pages/Notes"));
const Settings = lazy(() => import("./pages/Settings"));
const Auth = lazy(() => import("./pages/Auth"));
const NotFound = lazy(() => import("./pages/NotFound"));

function RequireAuth({ children }) {
  const { user, ready } = useSelector((s) => s.auth);
  const location = useLocation();
  if (!ready) return <PageSpinner />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return children;
}

export default function App() {
  const dispatch = useDispatch();
  const ready = useSelector((s) => s.auth.ready);
  const { pathname } = useLocation();

  useEffect(() => {
    dispatch(fetchMe());
  }, [dispatch]);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  if (!ready) return <PageSpinner full />;

  const guard = (el) => <RequireAuth>{el}</RequireAuth>;

  return (
    <>
      <Suspense fallback={<PageSpinner full />}>
        <Routes>
          <Route path="/login" element={<Auth mode="login" />} />
          <Route path="/register" element={<Auth mode="register" />} />
          <Route element={<Layout />}>
            <Route index element={<Home />} />
            <Route path="explore" element={<Explore />} />
            <Route path="search" element={<Search />} />
            <Route path="watch/:videoId" element={<Watch />} />
            <Route path="c/:username/*" element={<Channel />} />
            <Route path="playlist/:playlistId" element={<PlaylistPage />} />
            <Route path="upload" element={guard(<Upload />)} />
            <Route path="studio" element={guard(<Studio />)} />
            <Route path="following" element={guard(<Subscriptions />)} />
            <Route path="history" element={guard(<Library kind="history" />)} />
            <Route path="loved" element={guard(<Library kind="liked" />)} />
            <Route path="watchlist" element={guard(<Library kind="mylist" />)} />
            <Route path="notes" element={guard(<Notes />)} />
            {/* old paths */}
            <Route path="subscriptions" element={<Navigate to="/following" replace />} />
            <Route path="liked" element={<Navigate to="/loved" replace />} />
            <Route path="my-list" element={<Navigate to="/watchlist" replace />} />
            <Route path="settings" element={guard(<Settings />)} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </Suspense>
      <Toaster
        position="bottom-center"
        toastOptions={{ style: { background: "#161624", color: "#fff", border: "1px solid #2d2d40", borderRadius: "14px" }, duration: 2500 }}
      />
    </>
  );
}
