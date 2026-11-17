import { useCallback, useEffect, useRef, useState } from "react";
import { useSelector } from "react-redux";
import { useLocation, useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { api, errMsg } from "../api/client";

/** GET a URL and track { data, loading, error }. Pass null to skip. */
export function useFetch(url, { params, select = (d) => d.data, deps = [] } = {}) {
  const [state, setState] = useState({ data: null, loading: Boolean(url), error: null });
  const paramsKey = JSON.stringify(params || {});
  const selectRef = useRef(select);
  selectRef.current = select;

  const load = useCallback(async () => {
    if (!url) return setState({ data: null, loading: false, error: null });
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const { data } = await api.get(url, { params: JSON.parse(paramsKey) });
      setState({ data: selectRef.current(data), loading: false, error: null });
    } catch (err) {
      setState({ data: null, loading: false, error: errMsg(err) });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, paramsKey, ...deps]);

  useEffect(() => {
    load();
  }, [load]);

  const setData = useCallback((fn) => setState((s) => ({ ...s, data: typeof fn === "function" ? fn(s.data) : fn })), []);
  return { ...state, setData, reload: load };
}

/** Paginated list with "load more" support for endpoints returning { docs, hasNextPage }. */
export function usePaged(url, params = {}, limit = 24) {
  const [items, setItems] = useState([]);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const key = JSON.stringify(params);

  const fetchPage = useCallback(
    async (p) => {
      if (!url) return;
      setLoading(true);
      try {
        const { data } = await api.get(url, { params: { ...JSON.parse(key), page: p, limit } });
        setItems((prev) => (p === 1 ? data.data.docs : [...prev, ...data.data.docs]));
        setHasMore(data.data.hasNextPage);
        setPage(p);
        setError(null);
      } catch (err) {
        setError(errMsg(err));
      } finally {
        setLoading(false);
      }
    },
    [url, key, limit]
  );

  useEffect(() => {
    setItems([]);
    fetchPage(1);
  }, [fetchPage]);

  return { items, setItems, loading, error, hasMore, loadMore: () => !loading && hasMore && fetchPage(page + 1), reload: () => fetchPage(1) };
}

/** Calls `onVisible` when the returned ref's element scrolls into view (infinite scroll). */
export function useInView(onVisible, enabled = true) {
  const ref = useRef(null);
  const cb = useRef(onVisible);
  cb.current = onVisible;
  useEffect(() => {
    if (!enabled || !ref.current) return;
    const io = new IntersectionObserver(([e]) => e.isIntersecting && cb.current(), { rootMargin: "400px" });
    io.observe(ref.current);
    return () => io.disconnect();
  }, [enabled]);
  return ref;
}

/** Returns a guard: runs the action if signed in, otherwise sends the user to /login and back. */
export function useAuthGuard() {
  const user = useSelector((s) => s.auth.user);
  const navigate = useNavigate();
  const location = useLocation();
  return useCallback(
    (action) =>
      (...args) => {
        if (!user) {
          toast("Sign in to continue", { icon: "🔒" });
          navigate("/login", { state: { from: location.pathname + location.search } });
          return;
        }
        return action(...args);
      },
    [user, navigate, location]
  );
}

export const useUser = () => useSelector((s) => s.auth.user);

/** Returns shuffle(categories?, excludeId?) → navigates to a random video. */
export function useShuffle() {
  const navigate = useNavigate();
  return useCallback(
    async (categories, exclude) => {
      try {
        const { data } = await api.get("/videos/shuffle", {
          params: { categories: categories?.join(",") || undefined, exclude },
        });
        toast(`Shuffled: ${data.data.title}`, { icon: "🎲" });
        navigate(`/watch/${data.data._id}`);
      } catch (err) {
        toast.error(errMsg(err));
      }
    },
    [navigate]
  );
}
