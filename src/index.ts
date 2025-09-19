import "dotenv/config";
import express from "express";
import session from "express-session";
import cors from "cors";
import cookieParser from "cookie-parser";
import axios from "axios";
import { generateCodeVerifier, generateCodeChallenge, randomState } from "./pkce";
import jwt from "jsonwebtoken";
import { prisma } from "./db";


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

function signAppJWT(sub: string, extra?: Record<string, any>) {
  return jwt.sign(
    { sub, ...(extra || {}) },
    process.env.APP_JWT_SECRET!,
    { expiresIn: "15m" }
  );
}

// Verify incoming app JWT (from Authorization header)
function requireAppUser(req: express.Request): { sub: string } {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) throw new Error("Missing bearer token");
  const payload = jwt.verify(token, process.env.APP_JWT_SECRET!) as { sub: string };
  return payload;
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

    // 🔎 NEW STEP: Fetch Spotify profile
    const meRes = await axios.get("https://api.spotify.com/v1/me", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const spotifyUser = meRes.data; // { id, email, display_name, ... }

    await prisma.user.upsert({
      where: { id: spotifyUser.id },
      update: {
        email: spotifyUser.email,
        displayName: spotifyUser.display_name,
        avatarUrl: spotifyUser.images?.[0]?.url,
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: new Date(now * 1000 + expires_in * 1000),
      },
      create: {
        id: spotifyUser.id,
        email: spotifyUser.email,
        displayName: spotifyUser.display_name,
        avatarUrl: spotifyUser.images?.[0]?.url,
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: new Date(now * 1000 + expires_in * 1000),
      },
    });
    
    // ✅ Create short-lived app JWT tied to Spotify user id
    const appToken = signAppJWT(spotifyUser.id, {
      email: spotifyUser.email,
      name: spotifyUser.display_name,
      scope: SCOPES,
    });

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
    const { sub } = requireAppUser(req);
    const user = await prisma.user.findUnique({ where: { id: sub } });

    if (!user || !user.refreshToken)
      return res.status(401).json({ error: "No refresh token" });

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: user.refreshToken,
      client_id: SPOTIFY_CLIENT_ID!,
      client_secret: SPOTIFY_CLIENT_SECRET!,
    });

    const tokenRes = await axios.post(TOKEN_URL, body.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const { access_token, expires_in, refresh_token } = tokenRes.data;
    const newExpires = new Date(Date.now() + expires_in * 1000);

    await prisma.user.update({
      where: { id: sub },
      data: {
        accessToken: access_token,
        tokenExpiresAt: newExpires,
        ...(refresh_token && { refreshToken: refresh_token }),
      },
    });

    const newAppToken = signAppJWT(sub, {
      email: user.email,
      name: user.displayName,
      scope: SCOPES,
    });

    res.json({ token: newAppToken });
  } catch (e: any) {
    res.status(401).json({ error: "Refresh failed" });
  }
});

// 4) Example API proxy to test auth
app.get("/api/me", async (req, res) => {
  try {
    const { sub } = requireAppUser(req); // Spotify user ID from JWT
    const user = await prisma.user.findUnique({ where: { id: sub } });

    if (!user) return res.status(401).json({ error: "User not found" });

    res.json({
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
    });
  } catch (e) {
    res.status(401).json({ error: "Unauthorized" });
  }
});

app.post("/api/listening", async (req, res) => {
  try {
    const { sub } = requireAppUser(req);
    const { trackName, artistName, spotifyId, genre, energy, latitude, longitude } = req.body;

    const session = await prisma.listeningSession.create({
      data: {
        userId: sub,
        trackName,
        artistName,
        spotifyId,
        genre,
        energy,
        latitude,
        longitude,
      },
    });

    res.json(session);
  } catch {
    res.status(500).json({ error: "Failed to save listening session" });
  }
});

app.get("/api/listening/nearby", async (req, res) => {
  try {
    const { lat, lng, radius = 500 } = req.query;
    if (!lat || !lng) return res.status(400).json({ error: "Missing lat/lng" });

    const latNum = parseFloat(lat as string);
    const lngNum = parseFloat(lng as string);

    const sessions = await prisma.listeningSession.findMany({
      where: {
        createdAt: { gte: new Date(Date.now() - 1000 * 60 * 30) }, // last 30 min
      },
      include: { user: true },
    });

    // naive distance filter (upgrade to PostGIS later)
    const R = 6371000;
    const nearby = sessions.filter((s: any) => {
      if (!s.latitude || !s.longitude) return false;
      const dLat = (s.latitude - latNum) * (Math.PI / 180);
      const dLng = (s.longitude - lngNum) * (Math.PI / 180);
      const a =
        Math.sin(dLat / 2) ** 2 +
        Math.cos(latNum * Math.PI / 180) *
          Math.cos(s.latitude * Math.PI / 180) *
          Math.sin(dLng / 2) ** 2;
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      return R * c <= Number(radius);
    });

    res.json(nearby);
  } catch {
    res.status(500).json({ error: "Failed to fetch nearby listeners" });
  }
});

app.get("/", (_req, res) => res.send("Spotify Auth Server running"));
app.listen(Number(PORT), () => console.log(`Auth server on http://127.0.0.1:${PORT}`));
