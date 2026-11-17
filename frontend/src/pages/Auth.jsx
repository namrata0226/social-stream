import { BRAND } from "../brand";
import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import toast from "react-hot-toast";
import { HiEye, HiEyeOff } from "react-icons/hi";
import { api, errMsg } from "../api/client";
import { setUser } from "../store";
import { useUser } from "../hooks";
import { Logo } from "../components/Navbar";
import { Spinner } from "../components/ui";

export default function Auth({ mode }) {
  const isLogin = mode === "login";
  const user = useUser();
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from || "/";
  const [form, setForm] = useState({ identifier: "", fullName: "", username: "", email: "", password: "" });
  const [avatar, setAvatar] = useState(null);
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to={from} replace />;

  const set = (k) => (e) => setForm((s) => ({ ...s, [k]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      let res;
      if (isLogin) {
        res = await api.post("/users/login", { identifier: form.identifier, password: form.password });
      } else {
        const fd = new FormData();
        ["fullName", "username", "email", "password"].forEach((k) => fd.append(k, form[k]));
        if (avatar) fd.append("avatar", avatar);
        res = await api.post("/users/register", fd);
      }
      dispatch(setUser(res.data.data.user));
      toast.success(isLogin ? `Welcome back, ${res.data.data.user.fullName}!` : `Welcome to ${BRAND.name}!`);
      navigate(from, { replace: true });
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_#8b5cf640,_transparent_60%),radial-gradient(ellipse_at_bottom_right,_#22d3ee22,_transparent_50%)]" />
      <div className="relative w-full max-w-md">
        <div className="mb-8 flex justify-center"><Logo /></div>
        <form onSubmit={submit} className="card space-y-4 p-6 shadow-2xl sm:p-8">
          <div>
            <h1 className="text-2xl font-bold">{isLogin ? "Sign in" : "Create your account"}</h1>
            <p className="mt-1 text-sm text-zinc-400">{isLogin ? "Your Moments, notes and watchlist are waiting." : `Join ${BRAND.name} — ${BRAND.tagline.toLowerCase()}`}</p>
          </div>

          {isLogin ? (
            <div>
              <label className="label">Email or username</label>
              <input className="input" value={form.identifier} onChange={set("identifier")} required autoFocus autoComplete="username" />
            </div>
          ) : (
            <>
              <div className="flex items-center gap-4">
                <label className="relative flex h-16 w-16 shrink-0 cursor-pointer items-center justify-center overflow-hidden rounded-full bg-ink-700 text-xs text-zinc-400 hover:bg-ink-600">
                  {avatar ? <img src={URL.createObjectURL(avatar)} alt="" className="h-full w-full object-cover" /> : "Photo"}
                  <input type="file" accept="image/*" hidden onChange={(e) => setAvatar(e.target.files[0] || null)} />
                </label>
                <div className="flex-1">
                  <label className="label">Full name</label>
                  <input className="input" value={form.fullName} onChange={set("fullName")} required autoFocus maxLength={60} />
                </div>
              </div>
              <div>
                <label className="label">Username</label>
                <input className="input" value={form.username} onChange={(e) => setForm((s) => ({ ...s, username: e.target.value.toLowerCase().replace(/[^a-z0-9_.]/g, "") }))} required minLength={3} maxLength={30} placeholder="letters, numbers, _ or ." />
              </div>
              <div>
                <label className="label">Email</label>
                <input type="email" className="input" value={form.email} onChange={set("email")} required autoComplete="email" />
              </div>
            </>
          )}
          <div>
            <label className="label">Password</label>
            <div className="relative">
              <input type={show ? "text" : "password"} className="input pr-10" value={form.password} onChange={set("password")} required minLength={isLogin ? 1 : 6} autoComplete={isLogin ? "current-password" : "new-password"} />
              <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400" onClick={() => setShow((s) => !s)} aria-label="Toggle password visibility">
                {show ? <HiEyeOff /> : <HiEye />}
              </button>
            </div>
          </div>
          <button className="btn-primary w-full py-3" disabled={busy}>{busy && <Spinner className="h-4 w-4" />} {isLogin ? "Sign in" : "Create account"}</button>
          {isLogin && (
            <button type="button" className="w-full text-center text-xs text-zinc-500 hover:text-zinc-300" onClick={() => setForm((s) => ({ ...s, identifier: "demo", password: "demo123" }))}>
              Use demo account (demo / demo123)
            </button>
          )}
          <p className="text-center text-sm text-zinc-400">
            {isLogin ? "New here? " : "Already have an account? "}
            <Link to={isLogin ? "/register" : "/login"} state={location.state} className="font-semibold text-white hover:underline">{isLogin ? "Create an account" : "Sign in"}</Link>
          </p>
        </form>
        <p className="mt-6 text-center text-sm"><Link to="/" className="text-zinc-400 hover:text-white">← Continue browsing without signing in</Link></p>
      </div>
    </div>
  );
}
