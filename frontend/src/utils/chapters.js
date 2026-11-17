// Timestamps like 1:05, 12:30 or 1:02:03
export const TIMESTAMP_RE = /\b(?:\d{1,2}:)?\d{1,2}:\d{2}\b/g;

/** "1:02:03" → 3723, "90" → 90. Returns NaN for anything else. */
export function parseTime(str) {
  if (str == null || str === "") return NaN;
  const s = String(str).trim();
  if (/^\d+(\.\d+)?$/.test(s)) return Number(s);
  if (!/^(\d{1,2}:)?\d{1,2}:\d{2}$/.test(s)) return NaN;
  return s.split(":").reduce((acc, part) => acc * 60 + Number(part), 0);
}

/**
 * Chapters from a description: any lines that start with a timestamp, e.g.
 *   0:00 Intro
 *   1:30 - Setting up
 * Needs at least two chapters and one at 0:00, like most creators already write them.
 */
export function parseChapters(description = "", duration = 0) {
  const line = /^\s*(?:[-•*]\s*)?\(?((?:\d{1,2}:)?\d{1,2}:\d{2})\)?\s*[-–—:|]?\s*(.+?)\s*$/;
  const found = [];
  for (const raw of description.split("\n")) {
    const m = raw.match(line);
    if (!m) continue;
    const start = parseTime(m[1]);
    if (Number.isNaN(start) || (duration && start >= duration)) continue;
    if (found.some((c) => c.start === start)) continue;
    found.push({ start, title: m[2] });
  }
  found.sort((a, b) => a.start - b.start);
  if (found.length < 2 || found[0].start !== 0) return [];
  return found.map((c, i) => ({ ...c, end: found[i + 1]?.start ?? duration ?? c.start }));
}

export const chapterAt = (chapters, t) => {
  for (let i = chapters.length - 1; i >= 0; i--) if (t >= chapters[i].start) return chapters[i];
  return null;
};
