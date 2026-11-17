export const compact = (n = 0) =>
  new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n || 0);

export const views = (n = 0) => `${compact(n)} view${n === 1 ? "" : "s"}`;

export const duration = (sec = 0) => {
  sec = Math.max(0, Math.round(sec || 0));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = String(sec % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${s}` : `${m}:${s}`;
};

export const longDuration = (sec = 0) => {
  const h = Math.floor(sec / 3600);
  const m = Math.round((sec % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m`;
};

const UNITS = [
  ["year", 31536000],
  ["month", 2592000],
  ["week", 604800],
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
];
export const timeAgo = (date) => {
  const diff = (Date.now() - new Date(date).getTime()) / 1000;
  for (const [unit, secs] of UNITS) {
    const v = Math.floor(diff / secs);
    if (v >= 1) return `${v} ${unit}${v > 1 ? "s" : ""} ago`;
  }
  return "just now";
};

export const fullDate = (date) =>
  new Date(date).toLocaleDateString("en", { year: "numeric", month: "short", day: "numeric" });
