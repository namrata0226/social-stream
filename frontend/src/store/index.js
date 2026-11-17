import { configureStore, createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { api, setSessionExpiredHandler } from "../api/client";

export const fetchMe = createAsyncThunk("auth/me", async () => {
  try {
    const { data } = await api.get("/users/session");
    return data.data;
  } catch {
    return null;
  }
});

export const logout = createAsyncThunk("auth/logout", async () => {
  await api.post("/users/logout").catch(() => {});
});

const authSlice = createSlice({
  name: "auth",
  initialState: { user: null, ready: false },
  reducers: {
    setUser: (state, { payload }) => {
      state.user = payload;
      state.ready = true;
    },
    patchUser: (state, { payload }) => {
      if (state.user) state.user = { ...state.user, ...payload };
    },
    clearUser: (state) => {
      state.user = null;
    },
  },
  extraReducers: (b) => {
    b.addCase(fetchMe.fulfilled, (state, { payload }) => {
      state.user = payload;
      state.ready = true;
    });
    b.addCase(logout.fulfilled, (state) => {
      state.user = null;
    });
  },
});

export const { setUser, patchUser, clearUser } = authSlice.actions;

const uiSlice = createSlice({
  name: "ui",
  initialState: { sidebarOpen: typeof window !== "undefined" && window.innerWidth >= 1280 },
  reducers: {
    toggleSidebar: (s) => {
      s.sidebarOpen = !s.sidebarOpen;
    },
    setSidebar: (s, { payload }) => {
      s.sidebarOpen = payload;
    },
  },
});
export const { toggleSidebar, setSidebar } = uiSlice.actions;

export const store = configureStore({ reducer: { auth: authSlice.reducer, ui: uiSlice.reducer } });

setSessionExpiredHandler(() => store.dispatch(clearUser()));
