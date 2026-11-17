import { useState } from "react";
import { useDispatch } from "react-redux";
import toast from "react-hot-toast";
import { MdPhotoCamera } from "react-icons/md";
import { api, errMsg, mediaUrl } from "../api/client";
import { useUser } from "../hooks";
import { setUser } from "../store";
import { Avatar, Spinner } from "../components/ui";

function Section({ title, text, children }) {
  return (
    <section className="grid gap-4 border-b border-ink-800 py-8 md:grid-cols-[260px_1fr]">
      <div>
        <h2 className="font-semibold">{title}</h2>
        <p className="mt-1 text-sm text-zinc-400">{text}</p>
      </div>
      <div className="max-w-xl">{children}</div>
    </section>
  );
}

export default function Settings() {
  const user = useUser();
  const dispatch = useDispatch();
  const [profile, setProfile] = useState({ fullName: user.fullName, email: user.email, bio: user.bio || "" });
  const [pw, setPw] = useState({ oldPassword: "", newPassword: "", confirm: "" });
  const [busy, setBusy] = useState("");

  const run = async (key, fn) => {
    setBusy(key);
    try {
      await fn();
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy("");
    }
  };

  const uploadImage = (field, endpoint) => (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append(field, file);
    run(field, async () => {
      const { data } = await api.patch(endpoint, fd);
      dispatch(setUser(data.data));
      toast.success("Image updated");
    });
  };

  return (
    <div className="page max-w-5xl">
      <h1 className="page-title">Settings</h1>

      <div className="relative overflow-hidden rounded-2xl">
        <div className="h-40 bg-gradient-to-r from-brand/50 via-indigo-600/30 to-glow/30 sm:h-52">
          {user.coverImage?.url && <img src={mediaUrl(user.coverImage)} alt="" className="h-full w-full object-cover" />}
        </div>
        <label className="btn-ghost absolute right-3 top-3 cursor-pointer bg-black/50">
          {busy === "coverImage" ? <Spinner className="h-4 w-4" /> : <MdPhotoCamera />} Change cover
          <input type="file" accept="image/*" hidden onChange={uploadImage("coverImage", "/users/me/cover")} />
        </label>
        <label className="group absolute bottom-3 left-4 cursor-pointer">
          <Avatar user={user} size="h-24 w-24" className="border-4 border-ink-950 text-3xl" />
          <span className="absolute inset-0 flex items-center justify-center rounded-full bg-black/60 opacity-0 transition group-hover:opacity-100">
            {busy === "avatar" ? <Spinner /> : <MdPhotoCamera size={24} />}
          </span>
          <input type="file" accept="image/*" hidden onChange={uploadImage("avatar", "/users/me/avatar")} />
        </label>
      </div>

      <Section title="Profile" text="Your public name, contact email and channel description.">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            run("profile", async () => {
              const { data } = await api.patch("/users/me", profile);
              dispatch(setUser(data.data));
              toast.success("Profile saved");
            });
          }}
        >
          <div><label className="label">Display name</label><input className="input" value={profile.fullName} onChange={(e) => setProfile({ ...profile, fullName: e.target.value })} required maxLength={60} /></div>
          <div><label className="label">Username</label><input className="input opacity-60" value={`@${user.username}`} disabled /></div>
          <div><label className="label">Email</label><input type="email" className="input" value={profile.email} onChange={(e) => setProfile({ ...profile, email: e.target.value })} required /></div>
          <div><label className="label">Channel description</label><textarea className="input min-h-28" value={profile.bio} onChange={(e) => setProfile({ ...profile, bio: e.target.value })} maxLength={1000} /></div>
          <button className="btn-primary" disabled={busy === "profile"}>{busy === "profile" && <Spinner className="h-4 w-4" />} Save changes</button>
        </form>
      </Section>

      <Section title="Password" text="Use at least 6 characters.">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (pw.newPassword !== pw.confirm) return toast.error("Passwords don't match");
            run("pw", async () => {
              await api.post("/users/me/password", pw);
              setPw({ oldPassword: "", newPassword: "", confirm: "" });
              toast.success("Password changed");
            });
          }}
        >
          <div><label className="label">Current password</label><input type="password" className="input" value={pw.oldPassword} onChange={(e) => setPw({ ...pw, oldPassword: e.target.value })} required autoComplete="current-password" /></div>
          <div><label className="label">New password</label><input type="password" className="input" value={pw.newPassword} onChange={(e) => setPw({ ...pw, newPassword: e.target.value })} required minLength={6} autoComplete="new-password" /></div>
          <div><label className="label">Confirm new password</label><input type="password" className="input" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} required minLength={6} autoComplete="new-password" /></div>
          <button className="btn-primary" disabled={busy === "pw"}>{busy === "pw" && <Spinner className="h-4 w-4" />} Update password</button>
        </form>
      </Section>
    </div>
  );
}
