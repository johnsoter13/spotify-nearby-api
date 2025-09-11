import "dotenv/config";
import express from "express";
import session from "express-session";
import cors from "cors";
import cookieParser from "cookie-parser";
import axios from "axios";
import { generateCodeVerifier, generateCodeChallenge, randomState } from "./pkce";
import jwt from "jsonwebtoken";

const {
  SPOTIFY_CLIENT_ID,
  SPOTIFY_CLIENT_SECRET,
  SPOTIFY_REDIRECT_URI,
  PORT = "4000",
  SESSION_SECRET,
  ALLOWED_ORIGIN = "http://localhost:19006", // Expo web preview default; adjust
} = process.env;

if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET || !SPOTIFY_REDIRECT_URI || !SESSION_SECRET) {
  throw new Error("Missing required env vars.");
}

const app = express();

// CORS for your RN app / Expo dev
app.use(
  cors({
    origin: ALLOWED_ORIGIN.split(","),
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// Simple server session to hold PKCE + tokens server-side
app.use(
  session({
    name: "sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // set true behind HTTPS/proxy in prod
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

type SessionData = {
  codeVerifier?: string;
  oauthState?: string;
  accessToken?: string;
  refreshToken?: string;
  tokenExpiresAt?: number;
};

// Scopes you need (extend later for playlist write)
const SCOPES = [
  "user-read-email",
  "user-read-currently-playing",
  "user-read-playback-state",
  "playlist-modify-private",
  "playlist-modify-public",
].join(" ");

const AUTH_URL = "https://accounts.spotify.com/authorize";
const TOKEN_URL = "https://accounts.spotify.com/api/token";

// 1) Start login: generates PKCE + state, redirects to Spotify
app.get("/auth/login", (req, res) => {
  const sess = req.session as unknown as SessionData;
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = randomState();

  sess.codeVerifier = codeVerifier;
  sess.oauthState = state;

  const params = new URLSearchParams({
    client_id: SPOTIFY_CLIENT_ID!,
    response_type: "code",
    redirect_uri: SPOTIFY_REDIRECT_URI!,
    code_challenge_method: "S256",
    code_challenge: codeChallenge,
    state,
    scope: SCOPES,
    show_dialog: "true",
  });

  res.redirect(`${AUTH_URL}?${params.toString()}`);
});

// 2) Callback: validate state, exchange code for tokens
app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query as { code?: string; state?: string };
    const sess = req.session as unknown as SessionData;

    if (!code || !state) {
      return res.status(400).send("Missing code/state");
    }
    if (!sess.oauthState || state !== sess.oauthState) {
      return res.status(400).send("Invalid state");
    }
    if (!sess.codeVerifier) {
      return res.status(400).send("Missing PKCE code verifier");
    }

    // Exchange code for Spotify tokens
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: SPOTIFY_REDIRECT_URI!,
      client_id: SPOTIFY_CLIENT_ID!,
      code_verifier: sess.codeVerifier,
    });
    body.append("client_secret", SPOTIFY_CLIENT_SECRET!);

    const tokenRes = await axios.post(TOKEN_URL, body.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const { access_token, refresh_token, expires_in } = tokenRes.data;
    const now = Math.floor(Date.now() / 1000);

    // Save in session if you want server-side proxying
    sess.accessToken = access_token;
    sess.refreshToken = refresh_token;
    sess.tokenExpiresAt = now + expires_in - 30;

    // 🔎 NEW STEP: Fetch Spotify profile
    const meRes = await axios.get("https://api.spotify.com/v1/me", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const spotifyUser = meRes.data; // { id, email, display_name, ... }

    // ✅ Create app JWT with real Spotify ID
    const appToken = jwt.sign(
      {
        sub: spotifyUser.id,       // unique Spotify user ID
        email: spotifyUser.email,  // optional, include if you enabled `user-read-email`
        name: spotifyUser.display_name,
        scope: SCOPES,
      },
      process.env.APP_JWT_SECRET!,
      { expiresIn: "15m" }
    );

    // Redirect back to your app with the token
    const appScheme = process.env.APP_SCHEME || "nearby-spotify";
    const redirectUrl = `${appScheme}://auth?token=${appToken}`;

    res.redirect(redirectUrl);
  } catch (e: any) {
    console.error("Callback error", e.response?.data || e.message);
    res.status(500).send("Auth callback failed");
  }
});


// 3) Refresh endpoint (mobile app calls this when token is near expiry)
app.post("/auth/refresh", async (req, res) => {
  try {
    const sess = req.session as unknown as SessionData;
    if (!sess.refreshToken) return res.status(401).json({ error: "No refresh token" });

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: sess.refreshToken,
      client_id: SPOTIFY_CLIENT_ID!,
      client_secret: SPOTIFY_CLIENT_SECRET!,
    });

    const tokenRes = await axios.post(TOKEN_URL, body.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const { access_token, expires_in, refresh_token } = tokenRes.data;
    const now = Math.floor(Date.now() / 1000);

    sess.accessToken = access_token;
    if (refresh_token) sess.refreshToken = refresh_token; // sometimes Spotify rotates
    sess.tokenExpiresAt = now + expires_in - 30;

    res.json({
      accessToken: sess.accessToken,
      expiresAt: sess.tokenExpiresAt,
    });
  } catch (e: any) {
    console.error("Refresh error", e.response?.data || e.message);
    res.status(500).json({ error: "Refresh failed" });
  }
});

// 4) Example API proxy to test auth
app.get("/api/me", async (req, res) => {
  const sess = req.session as unknown as SessionData;
  if (!sess.accessToken) return res.status(401).json({ error: "Not authenticated" });

  try {
    const me = await axios.get("https://api.spotify.com/v1/me", {
      headers: { Authorization: `Bearer ${sess.accessToken}` },
    });
    res.json(me.data);
  } catch (e: any) {
    console.error("Spotify /me error", e.response?.data || e.message);
    res.status(500).json({ error: "Spotify request failed" });
  }
});

app.get("/", (_req, res) => res.send("Spotify Auth Server running"));
app.listen(Number(PORT), () => console.log(`Auth server on http://127.0.0.1:${PORT}`));
