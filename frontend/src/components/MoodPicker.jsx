import { useState } from "react";
import { GiPerspectiveDiceSixFacesRandom } from "react-icons/gi";
import { useFetch, useShuffle } from "../hooks";
import VideoRow from "./VideoRow";
import { Spinner } from "./ui";

// Moods map onto existing categories, so creators don't need to tag anything new
export const MOODS = [
  { key: "chill", emoji: "🌿", label: "Chill", hint: "slow down, breathe", categories: ["Music", "Travel", "Lifestyle"], tint: "from-emerald-500/25" },
  { key: "learn", emoji: "🧠", label: "Learn", hint: "level up a little", categories: ["Education", "Technology"], tint: "from-sky-500/25" },
  { key: "laugh", emoji: "😂", label: "Laugh", hint: "stuff that's funny", categories: ["Comedy"], tint: "from-amber-500/25" },
  { key: "hype", emoji: "⚡", label: "Hype", hint: "get the energy up", categories: ["Sports", "Gaming"], tint: "from-fuchsia-500/25" },
  { key: "cinematic", emoji: "🎬", label: "Cinematic", hint: "stories & films", categories: ["Movies"], tint: "from-violet-500/25" },
  { key: "hungry", emoji: "🍜", label: "Hungry", hint: "food & cooking", categories: ["Food"], tint: "from-orange-500/25" },
  { key: "curious", emoji: "🌍", label: "Curious", hint: "what's happening", categories: ["News", "Travel", "Technology"], tint: "from-cyan-500/25" },
];

function MoodResults({ mood }) {
  const shuffle = useShuffle();
  const { data, loading } = useFetch("/videos", {
    params: { category: mood.categories.join(","), sort: "popular", limit: 15 },
    select: (d) => d.data.docs,
  });

  return (
    <div className="mt-2 animate-rise">
      {loading && !data ? (
        <div className="flex justify-center py-10"><Spinner /></div>
      ) : !data?.length ? (
        <p className="px-4 py-6 text-sm text-zinc-400 sm:px-8">Nothing for this mood yet. Upload something {mood.emoji}</p>
      ) : (
        <VideoRow
          title={`${mood.emoji} ${mood.label} picks`}
          videos={data}
          link={`/explore?category=${encodeURIComponent(mood.categories.join(","))}`}
          extra={
            <button className="btn-ghost ml-auto py-1 text-xs" onClick={() => shuffle(mood.categories)}>
              <GiPerspectiveDiceSixFacesRandom size={16} className="text-glow-soft" /> Shuffle {mood.label.toLowerCase()}
            </button>
          }
        />
      )}
    </div>
  );
}

/** "What's your vibe?" — pick a mood and get a matching row, plus a mood-aware shuffle. */
export default function MoodPicker() {
  const [selected, setSelected] = useState(() => {
    try {
      return localStorage.getItem("kn.mood");
    } catch {
      return null;
    }
  });
  const mood = MOODS.find((m) => m.key === selected);

  const pick = (key) => {
    const next = key === selected ? null : key;
    setSelected(next);
    try {
      next ? localStorage.setItem("kn.mood", next) : localStorage.removeItem("kn.mood");
    } catch {}
  };

  return (
    <section>
      <div className="px-4 sm:px-8">
        <h2 className="font-display text-xl font-bold sm:text-2xl">
          What's your <span className="text-aurora">vibe</span> right now?
        </h2>
        <div className="no-scrollbar mt-3 flex gap-2 overflow-x-auto pb-1">
          {MOODS.map((m) => {
            const active = m.key === selected;
            return (
              <button
                key={m.key}
                onClick={() => pick(m.key)}
                className={`group flex shrink-0 items-center gap-3 rounded-2xl bg-gradient-to-br ${m.tint} to-transparent px-4 py-3 text-left ring-1 ring-inset transition hover:-translate-y-0.5 ${
                  active ? "ring-2 ring-brand shadow-lg shadow-brand/20" : "ring-white/10 hover:ring-white/25"
                }`}
              >
                <span className="text-2xl transition group-hover:scale-110">{m.emoji}</span>
                <span>
                  <span className="block text-sm font-semibold">{m.label}</span>
                  <span className="block text-[11px] text-zinc-400">{m.hint}</span>
                </span>
              </button>
            );
          })}
        </div>
      </div>
      {mood && <MoodResults key={mood.key} mood={mood} />}
    </section>
  );
}
