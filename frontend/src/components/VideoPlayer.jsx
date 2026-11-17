import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { FaPlay, FaPause } from "react-icons/fa";
import { HiVolumeUp, HiVolumeOff } from "react-icons/hi";
import { MdFullscreen, MdFullscreenExit, MdPictureInPictureAlt, MdOutlineCropLandscape, MdOutlineCropSquare, MdReplay10, MdForward10, MdSkipNext } from "react-icons/md";
import { IoSettingsSharp } from "react-icons/io5";
import { duration as fmt } from "../utils/format";
import { Spinner } from "./ui";
import { chapterAt } from "../utils/chapters";

const HEAT_BINS = 80;

// Shaka is ~870 KB, so it's loaded on demand the first time a player mounts
let shakaPromise = null;
const loadShaka = () =>
  (shakaPromise ??= import("shaka-player").then((m) => {
    const shaka = m.default ?? m;
    shaka.polyfill.installAll();
    return shaka;
  }));

const MIME_BY_EXT = {
  m3u8: "application/x-mpegurl",
  mpd: "application/dash+xml",
  mp4: "video/mp4",
  m4v: "video/mp4",
  webm: "video/webm",
  mov: "video/quicktime",
  mkv: "video/x-matroska",
};
const guessMime = (url) => MIME_BY_EXT[url.split(/[?#]/)[0].split(".").pop()?.toLowerCase()] ?? null;
let floatId = 0;

const SPEEDS = [0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.75, 2];

/**
 * Custom player UI on top of Shaka Player, which handles loading: HLS (.m3u8) and DASH (.mpd)
 * with adaptive bitrate, plus plain MP4/WebM files. Extras over a plain <video>:
 *  - Moments: emoji reactions float up at the second they were dropped, and a heat strip
 *    above the seek bar shows where viewers reacted most
 *  - Chapters: markers on the seek bar plus the current chapter name
 *  - Quality picker when the source has more than one rendition (HLS/DASH)
 * Imperative handle: getTime(), seekTo(t), burst(emoji)
 */
const VideoPlayer = forwardRef(function VideoPlayer(
  { src, poster, startAt = 0, onFirstPlay, onProgress, onEnded, nextVideo, onNext, theater, onToggleTheater, autoplay = true, moments = [], chapters = [], showMoments = true },
  ref
) {
  const videoRef = useRef(null);
  const wrapRef = useRef(null);
  const hideTimer = useRef(null);
  const started = useRef(false);
  const [playing, setPlaying] = useState(false);
  const [time, setTime] = useState(0);
  const [dur, setDur] = useState(0);
  const [buffered, setBuffered] = useState(0);
  const [volume, setVolume] = useState(() => Number(localStorage.getItem("kn.volume") ?? 1));
  const [muted, setMuted] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [showSettings, setShowSettings] = useState(false);
  const [controls, setControls] = useState(true);
  const [waiting, setWaiting] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [flash, setFlash] = useState(null);
  const [countdown, setCountdown] = useState(null);
  const [resumed, setResumed] = useState(false);
  const [floats, setFloats] = useState([]);
  const [hover, setHover] = useState(null); // { x, t } while hovering the seek bar
  const lastSecond = useRef(-1);
  const shakaRef = useRef(null);
  const [qualities, setQualities] = useState([]); // available heights, highest first
  const [quality, setQuality] = useState("auto"); // "auto" or a height
  const [activeHeight, setActiveHeight] = useState(null);
  const [loadError, setLoadError] = useState(null);

  const v = () => videoRef.current;

  const spawn = useCallback((emoji, mine = false) => {
    const id = ++floatId;
    const x = mine ? 50 + Math.random() * 10 : 62 + Math.random() * 30;
    setFloats((f) => [...f.slice(-24), { id, emoji, x, mine }]);
    setTimeout(() => setFloats((f) => f.filter((p) => p.id !== id)), 2300);
  }, []);

  useImperativeHandle(ref, () => ({
    getTime: () => v()?.currentTime || 0,
    seekTo: (t) => {
      const el = v();
      if (!el) return;
      el.currentTime = Math.max(0, Math.min(t, el.duration || t));
      el.play().catch(() => {});
    },
    burst: (emoji) => spawn(emoji, true),
  }), [spawn]);

  // Moments grouped by second, for replaying them during playback
  const bySecond = useMemo(() => {
    const map = new Map();
    for (const m of moments) {
      if (!map.has(m.t)) map.set(m.t, []);
      map.get(m.t).push(m);
    }
    return map;
  }, [moments]);

  const heat = useMemo(() => {
    if (!dur || !moments.length) return null;
    const bins = new Array(HEAT_BINS).fill(0);
    for (const m of moments) bins[Math.min(HEAT_BINS - 1, Math.floor((m.t / dur) * HEAT_BINS))] += m.n;
    // light smoothing so single reactions don't look like spikes
    const smooth = bins.map((b, i) => (bins[i - 1] || 0) * 0.25 + b * 0.5 + (bins[i + 1] || 0) * 0.25);
    const max = Math.max(...smooth);
    if (!max) return null;
    const pts = smooth.map((b, i) => `${((i + 0.5) / HEAT_BINS) * 100},${20 - (b / max) * 18}`);
    return `M0,20 L${pts.join(" L")} L100,20 Z`;
  }, [moments, dur]);

  const replayMoments = (cur) => {
    const sec = Math.floor(cur);
    const prev = lastSecond.current;
    lastSecond.current = sec;
    // only while playing straight through (not after a seek)
    if (!showMoments || prev < 0 || sec <= prev || sec - prev > 2) return;
    for (let s = prev + 1; s <= sec; s++) {
      const list = bySecond.get(s);
      if (!list) continue;
      let shown = 0;
      for (const m of list) {
        for (let k = 0; k < Math.min(m.n, 3) && shown < 5; k++, shown++) setTimeout(() => spawn(m.e), Math.random() * 700);
      }
    }
  };

  const chapter = chapters.length ? chapterAt(chapters, time) : null;

  // reset when the source changes
  useEffect(() => {
    started.current = false;
    setCountdown(null);
    setResumed(false);
    setTime(0);
    setWaiting(true);
    setFloats([]);
    lastSecond.current = -1;
  }, [src]);

  // Load the source through Shaka. Falls back to the browser's own loader if Shaka can't handle it.
  useEffect(() => {
    const el = videoRef.current;
    if (!el || !src) return;
    let cancelled = false;
    let player = null;
    setLoadError(null);
    setQualities([]);
    setQuality("auto");
    setActiveHeight(null);

    const nativeFallback = () => {
      if (cancelled) return;
      el.src = src;
      el.load();
    };

    const refreshTracks = () => {
      if (!player) return;
      const tracks = player.getVideoTracks();
      const heights = [...new Set(tracks.map((t) => t.height).filter(Boolean))].sort((a, b) => b - a);
      setQualities(heights.length > 1 ? heights : []);
      setActiveHeight(tracks.find((t) => t.active)?.height ?? null);
    };

    (async () => {
      try {
        const shaka = await loadShaka();
        if (cancelled) return;
        if (!shaka.Player.isBrowserSupported()) return nativeFallback();
        player = new shaka.Player();
        shakaRef.current = player;
        await player.attach(el);
        player.configure({ streaming: { bufferingGoal: 30, rebufferingGoal: 2 }, abr: { enabled: true } });
        player.addEventListener("trackschanged", refreshTracks);
        player.addEventListener("adaptation", refreshTracks);
        player.addEventListener("variantchanged", refreshTracks);
        player.addEventListener("error", (e) => {
          if (e.detail?.severity === 2) { // shaka.util.Error.Severity.CRITICAL
            setWaiting(false);
            setLoadError(`Playback error (code ${e.detail.code})`);
          }
        });
        if (cancelled) return;
        await player.load(src, null, guessMime(src));
        if (!cancelled) refreshTracks();
      } catch (err) {
        if (cancelled || err?.code === 7000) return; // 7000 = load interrupted by a newer load/destroy
        console.warn("Shaka could not load this source, using native playback", err);
        await player?.destroy().catch(() => {});
        if (shakaRef.current === player) shakaRef.current = null;
        player = null;
        nativeFallback();
      }
    })();

    return () => {
      cancelled = true;
      if (shakaRef.current === player) shakaRef.current = null;
      player?.destroy().catch(() => {});
    };
  }, [src]);

  const chooseQuality = (q) => {
    const player = shakaRef.current;
    setQuality(q);
    setShowSettings(false);
    if (!player) return;
    if (q === "auto") {
      player.configure({ abr: { enabled: true } });
      return;
    }
    player.configure({ abr: { enabled: false } });
    const track = player
      .getVideoTracks()
      .filter((t) => t.height === q)
      .sort((a, b) => b.bandwidth - a.bandwidth)[0];
    if (track) player.selectVideoTrack(track, true);
  };

  useEffect(() => {
    if (v()) {
      v().volume = volume;
      v().muted = muted;
    }
    try {
      localStorage.setItem("kn.volume", String(volume));
    } catch {}
  }, [volume, muted]);

  useEffect(() => {
    if (v()) v().playbackRate = speed;
  }, [speed]);

  const showFlash = (icon) => {
    setFlash({ icon, key: Date.now() });
  };

  const toggle = useCallback(() => {
    const el = v();
    if (!el) return;
    if (el.paused) el.play().catch(() => {});
    else el.pause();
  }, []);

  const seek = useCallback((delta) => {
    const el = v();
    if (!el) return;
    el.currentTime = Math.max(0, Math.min(el.duration || 0, el.currentTime + delta));
  }, []);

  const toggleFullscreen = useCallback(() => {
    if (document.fullscreenElement) document.exitFullscreen();
    else wrapRef.current?.requestFullscreen?.();
  }, []);

  const togglePip = async () => {
    try {
      if (document.pictureInPictureElement) await document.exitPictureInPicture();
      else await v()?.requestPictureInPicture();
    } catch {}
  };

  const poke = () => {
    setControls(true);
    clearTimeout(hideTimer.current);
    hideTimer.current = setTimeout(() => !v()?.paused && setControls(false), 2500);
  };

  useEffect(() => {
    const onFs = () => setFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener("fullscreenchange", onFs);
    return () => document.removeEventListener("fullscreenchange", onFs);
  }, []);

  // Keyboard shortcuts (ignored while typing)
  useEffect(() => {
    const onKey = (e) => {
      if (/input|textarea|select/i.test(document.activeElement?.tagName) || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = v();
      if (!el) return;
      const k = e.key.toLowerCase();
      const map = {
        " ": () => (toggle(), showFlash(el.paused ? "play" : "pause")),
        k: () => (toggle(), showFlash(el.paused ? "play" : "pause")),
        j: () => (seek(-10), showFlash("-10")),
        l: () => (seek(10), showFlash("+10")),
        arrowleft: () => (seek(-5), showFlash("-5")),
        arrowright: () => (seek(5), showFlash("+5")),
        arrowup: () => (setMuted(false), setVolume((x) => Math.min(1, +(x + 0.1).toFixed(2)))),
        arrowdown: () => setVolume((x) => Math.max(0, +(x - 0.1).toFixed(2))),
        m: () => setMuted((m) => !m),
        f: toggleFullscreen,
        t: () => onToggleTheater?.(),
        i: togglePip,
        ">": () => setSpeed((s) => SPEEDS[Math.min(SPEEDS.length - 1, SPEEDS.indexOf(s) + 1)]),
        "<": () => setSpeed((s) => SPEEDS[Math.max(0, SPEEDS.indexOf(s) - 1)]),
        "n": () => nextVideo && onNext?.(),
      };
      if (/^[0-9]$/.test(k) && el.duration) {
        e.preventDefault();
        el.currentTime = (Number(k) / 10) * el.duration;
        return poke();
      }
      if (map[k]) {
        e.preventDefault();
        map[k]();
        poke();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [toggle, seek, toggleFullscreen, onToggleTheater, nextVideo, onNext]);

  // Report progress every 5s while playing
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => v() && onProgress?.(v().currentTime, v().duration), 5000);
    return () => clearInterval(t);
  }, [playing, onProgress]);

  // Save on unmount / tab close
  useEffect(() => {
    const el = videoRef.current; // the ref is already detached when cleanup runs on unmount
    const save = () => el && started.current && el.currentTime > 0 && onProgress?.(el.currentTime, el.duration);
    window.addEventListener("pagehide", save);
    return () => {
      save();
      window.removeEventListener("pagehide", save);
    };
  }, [src, onProgress]);

  // Autoplay-next countdown
  useEffect(() => {
    if (countdown === null) return;
    if (countdown <= 0) {
      setCountdown(null);
      onNext?.();
      return;
    }
    const t = setTimeout(() => setCountdown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [countdown, onNext]);

  const pct = dur ? (time / dur) * 100 : 0;

  return (
    <div
      ref={wrapRef}
      className={`group relative w-full select-none overflow-hidden bg-black ${theater || fullscreen ? "" : "rounded-xl"} ${controls || !playing ? "" : "cursor-none"}`}
      onMouseMove={poke}
      onMouseLeave={() => playing && setControls(false)}
    >
      <video
        ref={videoRef}
        poster={poster}
        playsInline
        className={`mx-auto block w-full ${theater || fullscreen ? "max-h-[calc(100vh-4rem)]" : ""} ${fullscreen ? "h-screen max-h-none" : ""} aspect-video`}
        onClick={toggle}
        onDoubleClick={toggleFullscreen}
        onLoadedMetadata={(e) => {
          setDur(e.target.duration);
          if (startAt >= 1 && startAt < e.target.duration - 2) {
            e.target.currentTime = startAt;
            setResumed(true);
            setTimeout(() => setResumed(false), 3500);
          }
          if (autoplay) {
            // Browsers may block autoplay with sound — fall back to muted playback with an unmute prompt
            e.target.play().catch(() => {
              setMuted(true);
              e.target.muted = true;
              e.target.play().catch(() => setWaiting(false));
            });
          } else setWaiting(false);
        }}
        onTimeUpdate={(e) => {
          setTime(e.target.currentTime);
          if (!e.target.paused) replayMoments(e.target.currentTime);
          else lastSecond.current = Math.floor(e.target.currentTime);
        }}
        onSeeked={(e) => (lastSecond.current = Math.floor(e.target.currentTime))}
        onProgress={(e) => {
          const b = e.target.buffered;
          if (b.length) setBuffered(b.end(b.length - 1));
        }}
        onPlay={() => {
          setPlaying(true);
          setCountdown(null);
          poke();
          if (!started.current) {
            started.current = true;
            onFirstPlay?.();
          }
        }}
        onPause={() => (setPlaying(false), setControls(true))}
        onError={() => !shakaRef.current && (setWaiting(false), setLoadError("This video can't be played in your browser."))}
        onWaiting={() => setWaiting(true)}
        onPlaying={() => setWaiting(false)}
        onCanPlay={() => setWaiting(false)}
        onEnded={() => {
          setPlaying(false);
          onProgress?.(v().duration, v().duration);
          onEnded?.();
          if (nextVideo) setCountdown(8);
        }}
      />

      {loadError && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-black/80 p-6 text-center animate-fadeIn">
          <p className="font-semibold">Couldn't play this video</p>
          <p className="text-sm text-zinc-400">{loadError}</p>
        </div>
      )}

      {waiting && playing && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center"><Spinner className="h-12 w-12" /></div>
      )}

      {/* Floating Moments */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {floats.map((f) => (
          <span
            key={f.id}
            className={`absolute bottom-20 animate-floatUp select-none ${f.mine ? "text-5xl drop-shadow-[0_0_14px_rgba(139,92,246,0.9)]" : "text-3xl drop-shadow-lg"}`}
            style={{ left: `${f.x}%` }}
          >
            {f.emoji}
          </span>
        ))}
      </div>

      {flash && (
        <div key={flash.key} className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-black/60 text-lg font-bold opacity-0 [animation:fadeIn_.15s_ease-out_reverse_.4s_both]">
            {flash.icon === "play" ? <FaPlay /> : flash.icon === "pause" ? <FaPause /> : flash.icon}
          </div>
        </div>
      )}

      {muted && playing && (
        <button onClick={() => (setMuted(false), setVolume((x) => x || 1))} className="absolute right-4 top-4 flex items-center gap-2 rounded-lg bg-black/70 px-3 py-2 text-sm font-semibold hover:bg-black/90 animate-fadeIn">
          <HiVolumeOff size={18} /> Tap to unmute
        </button>
      )}

      {!playing && !waiting && !loadError && countdown === null && (
        <button onClick={toggle} className="absolute left-1/2 top-1/2 flex h-16 w-16 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-2xl bg-gradient-to-br from-brand to-indigo-500 shadow-2xl shadow-brand/40 transition hover:scale-110" aria-label="Play">
          <FaPlay size={22} className="ml-1" />
        </button>
      )}

      {resumed && (
        <div className="absolute left-4 top-4 rounded-lg bg-black/70 px-3 py-2 text-sm animate-fadeIn">
          Resumed from {fmt(startAt)} ·{" "}
          <button className="font-semibold text-brand-soft hover:underline" onClick={() => (v().currentTime = 0, setResumed(false))}>Start over</button>
        </div>
      )}

      {countdown !== null && nextVideo && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/80 animate-fadeIn">
          <div className="w-80 max-w-[90%] text-center">
            <p className="text-sm text-zinc-400">Up next in {countdown}s</p>
            <img src={nextVideo.poster} alt="" className="mx-auto mt-3 aspect-video w-full rounded-lg object-cover" />
            <p className="mt-3 line-clamp-2 font-semibold">{nextVideo.title}</p>
            <div className="mt-4 flex justify-center gap-2">
              <button className="btn-ghost" onClick={() => setCountdown(null)}>Cancel</button>
              <button className="btn-light" onClick={() => (setCountdown(null), onNext())}><MdSkipNext size={20} /> Play now</button>
            </div>
          </div>
        </div>
      )}

      {/* Controls */}
      <div className={`absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 via-black/40 to-transparent px-3 pb-2 pt-12 transition-opacity duration-200 ${controls || !playing ? "opacity-100" : "opacity-0"}`}>
        {heat && showMoments && (
          <svg viewBox="0 0 100 20" preserveAspectRatio="none" className="pointer-events-none mb-0.5 h-5 w-full opacity-80" aria-hidden="true">
            <defs>
              <linearGradient id="heatFill" x1="0" x2="1">
                <stop offset="0" stopColor="#8b5cf6" stopOpacity=".7" />
                <stop offset="1" stopColor="#22d3ee" stopOpacity=".7" />
              </linearGradient>
            </defs>
            <path d={heat} fill="url(#heatFill)" />
          </svg>
        )}
        <div
          className="group/seek relative h-4 cursor-pointer"
          onMouseMove={(e) => {
            const r = e.currentTarget.getBoundingClientRect();
            const x = Math.max(0, Math.min(r.width, e.clientX - r.left));
            setHover({ x, w: r.width, t: dur ? (x / r.width) * dur : 0 });
          }}
          onMouseLeave={() => setHover(null)}
          onClick={(e) => {
            const r = e.currentTarget.getBoundingClientRect();
            if (dur) v().currentTime = ((e.clientX - r.left) / r.width) * dur;
          }}
        >
          {hover && dur > 0 && (
            <div
              className="pointer-events-none absolute bottom-6 -translate-x-1/2 whitespace-nowrap rounded-lg bg-ink-900/95 px-2 py-1 text-center text-xs font-semibold shadow-xl"
              style={{ left: Math.max(40, Math.min(hover.w - 40, hover.x)) }}
            >
              {chapters.length > 0 && <span className="block max-w-[200px] truncate text-[11px] font-medium text-zinc-300">{chapterAt(chapters, hover.t)?.title}</span>}
              {fmt(hover.t)}
            </div>
          )}
          <div className="absolute inset-x-0 top-1/2 h-1 -translate-y-1/2 rounded-full bg-white/20 transition-all group-hover/seek:h-1.5">
            <div className="absolute inset-y-0 left-0 rounded-full bg-white/30" style={{ width: `${dur ? (buffered / dur) * 100 : 0}%` }} />
            <div className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-brand to-glow" style={{ width: `${pct}%` }} />
            {dur > 0 && chapters.slice(1).map((c) => (
              <span key={c.start} className="absolute inset-y-0 w-[3px] -translate-x-1/2 bg-black/80" style={{ left: `${(c.start / dur) * 100}%` }} />
            ))}
          </div>
          <input
            type="range"
            min={0}
            max={dur || 0}
            step="0.1"
            value={time}
            onChange={(e) => (v().currentTime = Number(e.target.value))}
            className="absolute inset-0 w-full cursor-pointer opacity-0"
            aria-label="Seek"
          />
          <div className="pointer-events-none absolute top-1/2 h-3.5 w-3.5 -translate-x-1/2 -translate-y-1/2 scale-0 rounded-full bg-white shadow-[0_0_10px_rgba(34,211,238,0.8)] transition group-hover/seek:scale-100" style={{ left: `${pct}%` }} />
        </div>

        <div className="mt-1 flex items-center gap-1 text-white">
          <button className="btn-icon" onClick={toggle} aria-label={playing ? "Pause" : "Play"}>{playing ? <FaPause /> : <FaPlay />}</button>
          <button className="btn-icon hidden sm:inline-flex" onClick={() => seek(-10)} aria-label="Back 10 seconds"><MdReplay10 size={22} /></button>
          <button className="btn-icon hidden sm:inline-flex" onClick={() => seek(10)} aria-label="Forward 10 seconds"><MdForward10 size={22} /></button>
          {nextVideo && <button className="btn-icon" onClick={onNext} title="Next (N)"><MdSkipNext size={24} /></button>}
          <div className="group/vol flex items-center">
            <button className="btn-icon" onClick={() => setMuted((m) => !m)} aria-label="Mute">{muted || volume === 0 ? <HiVolumeOff size={20} /> : <HiVolumeUp size={20} />}</button>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={muted ? 0 : volume}
              onChange={(e) => (setVolume(Number(e.target.value)), setMuted(false))}
              className="w-0 accent-white transition-all group-hover/vol:w-20"
              aria-label="Volume"
            />
          </div>
          <span className="ml-2 shrink-0 text-xs tabular-nums text-zinc-200">{fmt(time)} / {fmt(dur)}</span>
          {chapter && <span className="ml-2 hidden min-w-0 truncate text-xs font-semibold text-zinc-200 sm:inline">· {chapter.title}</span>}

          <div className="ml-auto flex items-center">
            <div className="relative">
              <button className="btn-icon" onClick={() => setShowSettings((s) => !s)} aria-label="Settings">
                <IoSettingsSharp size={18} className={showSettings ? "rotate-45 transition" : "transition"} />
              </button>
              {speed !== 1 && <span className="pointer-events-none absolute -top-0.5 right-0 rounded bg-brand px-1 text-[9px] font-bold">{speed}x</span>}
              {showSettings && (
                <div className="absolute bottom-12 right-0 max-h-80 w-40 overflow-y-auto rounded-lg bg-ink-900/95 py-1 text-sm shadow-2xl">
                  {qualities.length > 0 && (
                    <>
                      <p className="px-3 py-1 text-xs text-zinc-400">Quality</p>
                      {["auto", ...qualities].map((q) => (
                        <button key={q} onClick={() => chooseQuality(q)} className={`block w-full px-3 py-1.5 text-left hover:bg-white/10 ${q === quality ? "text-brand-soft" : ""}`}>
                          {q === "auto" ? `Auto${quality === "auto" && activeHeight ? ` (${activeHeight}p)` : ""}` : `${q}p`}
                        </button>
                      ))}
                      <div className="my-1 border-t border-white/10" />
                    </>
                  )}
                  <p className="px-3 py-1 text-xs text-zinc-400">Playback speed</p>
                  {SPEEDS.map((s) => (
                    <button key={s} onClick={() => (setSpeed(s), setShowSettings(false))} className={`block w-full px-3 py-1.5 text-left hover:bg-white/10 ${s === speed ? "text-brand-soft" : ""}`}>
                      {s === 1 ? "Normal" : `${s}x`}
                    </button>
                  ))}
                </div>
              )}
            </div>
            {document.pictureInPictureEnabled && <button className="btn-icon hidden sm:inline-flex" onClick={togglePip} title="Picture-in-picture (I)"><MdPictureInPictureAlt size={20} /></button>}
            {onToggleTheater && !fullscreen && (
              <button className="btn-icon hidden lg:inline-flex" onClick={onToggleTheater} title="Theater mode (T)">
                {theater ? <MdOutlineCropSquare size={22} /> : <MdOutlineCropLandscape size={22} />}
              </button>
            )}
            <button className="btn-icon" onClick={toggleFullscreen} title="Fullscreen (F)">{fullscreen ? <MdFullscreenExit size={24} /> : <MdFullscreen size={24} />}</button>
          </div>
        </div>
      </div>
    </div>
  );
});

export default VideoPlayer;
