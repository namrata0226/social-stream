import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { MdCloudUpload, MdCheckCircle, MdImage } from "react-icons/md";
import axios from "axios";
import { api, errMsg } from "../api/client";
import { useFetch } from "../hooks";
import { duration as fmt } from "../utils/format";
import { Spinner, Toggle } from "../components/ui";

const MAX_MB = 1024;
const CLOUDINARY_FREE_MAX_MB = 100; // Cloudinary's free plan caps a single video at 100 MB

// Upload one file straight to Cloudinary with the signed params from the API
async function uploadToCloudinary(file, sig, resourceType, { signal, onProgress }) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("api_key", sig.apiKey);
  fd.append("timestamp", String(sig.timestamp));
  fd.append("signature", sig.signature);
  fd.append("folder", sig.folder);
  const { data } = await axios.post(`https://api.cloudinary.com/v1_1/${sig.cloudName}/${resourceType}/upload`, fd, {
    signal,
    onUploadProgress: (p) => onProgress?.(p.loaded / (p.total || 1)),
  });
  return data.public_id;
}

// Grab a frame from a video at `time` seconds as a JPEG blob
function captureFrame(src, time) {
  return new Promise((resolve) => {
    const v = document.createElement("video");
    v.muted = true;
    v.preload = "auto";
    v.src = src;
    v.onloadeddata = () => (v.currentTime = Math.min(time, Math.max(0, v.duration - 0.1)));
    v.onseeked = () => {
      const c = document.createElement("canvas");
      c.width = Math.min(1280, v.videoWidth || 1280);
      c.height = Math.round(c.width * ((v.videoHeight || 720) / (v.videoWidth || 1280)));
      c.getContext("2d").drawImage(v, 0, 0, c.width, c.height);
      c.toBlob((b) => resolve(b), "image/jpeg", 0.85);
    };
    v.onerror = () => resolve(null);
  });
}

export default function Upload() {
  const navigate = useNavigate();
  const { data: categories } = useFetch("/videos/categories");
  const inputRef = useRef(null);
  const thumbInput = useRef(null);
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState("");
  const [meta, setMeta] = useState({ duration: 0 });
  const [frames, setFrames] = useState([]); // [{blob, url}]
  const [custom, setCustom] = useState(null); // {file, url}
  const [selected, setSelected] = useState(0); // index into frames or "custom"
  const [form, setForm] = useState({ title: "", description: "", category: "Other", tags: "", isPublished: true });
  const [progress, setProgress] = useState(null);
  const [dragging, setDragging] = useState(false);
  // { enabled, video, image } — when Cloudinary is configured, files skip the API (needed on Vercel)
  const { data: direct } = useFetch("/uploads/direct");
  const abortRef = useRef(null);

  useEffect(() => () => {
    if (preview) URL.revokeObjectURL(preview);
  }, [preview]);

  const pick = async (f) => {
    if (!f) return;
    if (!f.type.startsWith("video/")) return toast.error("Please choose a video file");
    const limit = direct?.enabled ? CLOUDINARY_FREE_MAX_MB : MAX_MB;
    if (f.size > limit * 1024 * 1024) return toast.error(`Max file size is ${limit} MB`);
    const url = URL.createObjectURL(f);
    setFile(f);
    setPreview(url);
    setForm((s) => ({ ...s, title: s.title || f.name.replace(/\.[^.]+$/, "").replace(/[_-]+/g, " ").slice(0, 120) }));
    setFrames([]);
    setSelected(0);

    const probe = document.createElement("video");
    probe.preload = "metadata";
    probe.src = url;
    probe.onerror = () => {
      // e.g. .mkv/.avi the browser can't decode: still uploadable, but needs a custom thumbnail
      setSelected("custom");
      toast("Preview unavailable for this format — please upload a thumbnail image", { icon: "🖼️" });
    };
    probe.onloadedmetadata = async () => {
      const d = probe.duration || 0;
      setMeta({ duration: d });
      const shots = [];
      for (const t of [d * 0.1, d * 0.4, d * 0.75]) {
        const blob = await captureFrame(url, t);
        if (blob) shots.push({ blob, url: URL.createObjectURL(blob) });
      }
      setFrames(shots);
      if (!shots.length) setSelected("custom");
    };
  };

  const thumbnailBlob = () => (selected === "custom" ? custom?.file : frames[selected]?.blob);

  const submit = async (e) => {
    e.preventDefault();
    const thumb = thumbnailBlob();
    if (!file) return toast.error("Choose a video first");
    if (!form.title.trim()) return toast.error("Title is required");
    if (!thumb) return toast.error("Choose or upload a thumbnail");

    const controller = new AbortController();
    abortRef.current = controller;
    setProgress(0);
    try {
      let data;
      if (direct?.enabled) {
        // 1) thumbnail + video straight to Cloudinary, 2) tell the API about them
        const thumbFile = thumb instanceof File ? thumb : new File([thumb], "thumbnail.jpg", { type: "image/jpeg" });
        const thumbnailPublicId = await uploadToCloudinary(thumbFile, direct.image, "image", { signal: controller.signal });
        const videoPublicId = await uploadToCloudinary(file, direct.video, "video", {
          signal: controller.signal,
          onProgress: (f) => setProgress(Math.min(99, Math.round(f * 100))),
        });
        setProgress(100);
        ({ data } = await api.post("/videos", { ...form, duration: meta.duration || 0, videoPublicId, thumbnailPublicId }));
      } else {
        const fd = new FormData();
        fd.append("videoFile", file);
        fd.append("thumbnail", thumb, thumb.name || "thumbnail.jpg");
        Object.entries(form).forEach(([k, v]) => fd.append(k, String(v)));
        fd.append("duration", String(meta.duration || 0));
        ({ data } = await api.post("/videos", fd, {
          signal: controller.signal,
          onUploadProgress: (p) => setProgress(Math.round((p.loaded / (p.total || 1)) * 100)),
        }));
      }
      toast.success("Video published!");
      navigate(`/watch/${data.data._id}`);
    } catch (err) {
      if (err.name !== "CanceledError") toast.error(errMsg(err));
      setProgress(null);
    }
  };

  const set = (k) => (e) => setForm((s) => ({ ...s, [k]: e?.target ? e.target.value : e }));

  if (!file) {
    return (
      <div className="page max-w-3xl">
        <h1 className="page-title">Upload video</h1>
        <div
          onDragOver={(e) => (e.preventDefault(), setDragging(true))}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => (e.preventDefault(), setDragging(false), pick(e.dataTransfer.files[0]))}
          onClick={() => inputRef.current.click()}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed px-6 py-24 text-center transition ${dragging ? "border-brand bg-brand/10" : "border-ink-600 hover:border-zinc-400"}`}
        >
          <div className="mb-4 rounded-full bg-ink-800 p-6"><MdCloudUpload size={48} className="text-brand" /></div>
          <p className="text-lg font-semibold">Drag and drop a video to upload</p>
          <p className="mt-1 text-sm text-zinc-400">MP4, WebM or MOV · up to {direct?.enabled ? CLOUDINARY_FREE_MAX_MB : MAX_MB} MB</p>
          <button type="button" className="btn-primary mt-6">Select file</button>
          <input ref={inputRef} type="file" accept="video/*" hidden onChange={(e) => pick(e.target.files[0])} />
        </div>
      </div>
    );
  }

  const uploading = progress !== null;

  return (
    <form onSubmit={submit} className="page max-w-6xl">
      <h1 className="page-title">Video details</h1>
      <div className="grid gap-8 lg:grid-cols-[1fr_380px]">
        <fieldset disabled={uploading} className="space-y-5">
          <div>
            <label className="label">Title *</label>
            <input className="input" value={form.title} onChange={set("title")} maxLength={120} required />
            <p className="mt-1 text-right text-xs text-zinc-500">{form.title.length}/120</p>
          </div>
          <div>
            <label className="label">Description</label>
            <textarea className="input min-h-36" value={form.description} onChange={set("description")} maxLength={5000} placeholder="Tell viewers about your video" />
          </div>
          <div>
            <label className="label">Thumbnail</label>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {frames.map((f, i) => (
                <button type="button" key={f.url} onClick={() => setSelected(i)} className={`relative aspect-video overflow-hidden rounded-lg ring-2 ${selected === i ? "ring-brand" : "ring-transparent hover:ring-ink-500"}`}>
                  <img src={f.url} alt="" className="h-full w-full object-cover" />
                  {selected === i && <MdCheckCircle className="absolute right-1 top-1 text-brand" size={20} />}
                </button>
              ))}
              {frames.length === 0 && meta.duration > 0 && (
                <div className="flex aspect-video items-center justify-center rounded-lg bg-ink-800"><Spinner className="h-5 w-5" /></div>
              )}
              <button type="button" onClick={() => thumbInput.current.click()} className={`relative flex aspect-video flex-col items-center justify-center overflow-hidden rounded-lg border border-dashed border-ink-500 text-xs text-zinc-400 ring-2 hover:border-zinc-300 ${selected === "custom" ? "ring-brand" : "ring-transparent"}`}>
                {custom ? <img src={custom.url} alt="" className="absolute inset-0 h-full w-full object-cover" /> : (<><MdImage size={22} /> Upload image</>)}
              </button>
              <input
                ref={thumbInput}
                type="file"
                accept="image/*"
                hidden
                onChange={(e) => {
                  const f = e.target.files[0];
                  if (!f) return;
                  setCustom({ file: f, url: URL.createObjectURL(f) });
                  setSelected("custom");
                }}
              />
            </div>
          </div>
          <div className="grid gap-5 sm:grid-cols-2">
            <div>
              <label className="label">Category</label>
              <select className="input" value={form.category} onChange={set("category")}>
                {(categories || ["Other"]).map((c) => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Tags</label>
              <input className="input" value={form.tags} onChange={set("tags")} placeholder="comma, separated, tags" />
            </div>
          </div>
          <Toggle checked={form.isPublished} onChange={set("isPublished")} label={form.isPublished ? "Public — everyone can watch" : "Draft — only you can see it"} />
        </fieldset>

        <aside className="space-y-4">
          <div className="card overflow-hidden">
            <video src={preview} controls className="aspect-video w-full bg-black" />
            <div className="space-y-1 p-4 text-sm">
              <p className="text-zinc-400">File</p>
              <p className="truncate">{file.name}</p>
              <p className="pt-2 text-zinc-400">Size · Duration</p>
              <p>{(file.size / 1024 / 1024).toFixed(1)} MB · {fmt(meta.duration)}</p>
            </div>
          </div>
          {uploading && (
            <div className="card p-4">
              <div className="mb-2 flex justify-between text-sm"><span>{progress < 100 ? "Uploading…" : "Processing…"}</span><span>{progress}%</span></div>
              <div className="h-2 overflow-hidden rounded-full bg-ink-700"><div className="h-full bg-brand transition-all" style={{ width: `${progress}%` }} /></div>
            </div>
          )}
          <div className="flex gap-2">
            {uploading ? (
              <button type="button" className="btn-ghost flex-1" onClick={() => abortRef.current?.abort()}>Cancel upload</button>
            ) : (
              <button type="button" className="btn-ghost flex-1" onClick={() => (setFile(null), setPreview(""), setCustom(null))}>Change file</button>
            )}
            <button className="btn-primary flex-1" disabled={uploading}>{uploading && <Spinner className="h-4 w-4" />} {form.isPublished ? "Publish" : "Save draft"}</button>
          </div>
        </aside>
      </div>
    </form>
  );
}
