import axios from "axios";

const ORIGIN = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

export const api = axios.create({ baseURL: `${ORIGIN}/api/v1`, withCredentials: true });

// Resolve media URLs: local uploads are relative (/uploads/...), Cloudinary/external are absolute
export const mediaUrl = (asset) => {
  const url = typeof asset === "string" ? asset : asset?.url;
  if (!url) return "";
  return url.startsWith("/") ? `${ORIGIN}${url}` : url;
};

export const errMsg = (err) =>
  err?.response?.data?.message || (err?.code === "ERR_NETWORK" ? "Cannot reach the server" : err?.message) || "Something went wrong";

// ---- Transparent access-token refresh on 401 ----
let onSessionExpired = () => {};
export const setSessionExpiredHandler = (fn) => (onSessionExpired = fn);

let refreshing = null;
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    const status = error.response?.status;
    const isAuthCall = /\/users\/(login|register|refresh-token|session)/.test(original?.url || "");
    if (status !== 401 || original?._retried || isAuthCall) throw error;

    original._retried = true;
    try {
      refreshing ??= api.post("/users/refresh-token").finally(() => (refreshing = null));
      await refreshing;
      return api(original);
    } catch {
      onSessionExpired();
      throw error;
    }
  }
);
