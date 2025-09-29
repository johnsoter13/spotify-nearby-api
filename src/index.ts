// src/index.ts
import "dotenv/config";
import express, { NextFunction, Request, Response } from "express";
import session from "express-session";
import cors from "cors";
import cookieParser from "cookie-parser";
import axios from "axios";
import jwt, { TokenExpiredError, JwtPayload } from "jsonwebtoken";
import { generateCodeVerifier, generateCodeChallenge, randomState } from "./pkce";
import { prisma } from "./db";

// ---------- Env ----------
const {
  SPOTIFY_CLIENT_ID,
  SPOTIFY_CLIENT_SECRET,
  SPOTIFY_REDIRECT_URI,
  APP_JWT_SECRET,
  APP_SCHEME = "nearby-spotify",
  PORT = "4000",
  SESSION_SECRET,
  ALLOWED_ORIGIN = "http://localhost:19006",
  NODE_ENV = "development",
} = process.env;

if (
  !SPOTIFY_CLIENT_ID ||
  !SPOTIFY_CLIENT_SECRET ||
  !SPOTIFY_REDIRECT_URI ||
  !SESSION_SECRET ||
  !APP_JWT_SECRET
) {
  throw new Error("Missing required env vars.");
}

const IS_PROD = NODE_ENV === "production";

// If you deploy behind a proxy/ingress in prod, trust it so secure cookies work
if (IS_PROD) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  // @ts-ignore - express types accept number|boolean|string
  // (Heroku/Render often need '1')
}

// ---------- Types ----------
declare module "express-session" {
  // Properly augment SessionData instead of casting
  interface SessionData {
    codeVerifier?: string;
    oauthState?: string;
  }
}

type AppUserPayload = JwtPayload & {
  sub: string; // Spotify user ID
  email?: string | null;
  name?: string | null;
  scope?: string;
};

declare global {
  namespace Express {
    interface Request {
      appUser?: AppUserPayload;
    }
  }
}

// ---------- Auth helpers ----------
function signAppJWT(sub: string, extra?: Partial<AppUserPayload>) {
  return jwt.sign({ sub, ...(extra || {}) }, APP_JWT_SECRET!, { expiresIn: "15m" });
}

// Middleware: require a valid (non-expired) app token and attach req.appUser
function requireAppUser(req: Request, res: Response, next: NextFunction) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Missing token" });

    const payload = jwt.verify(token, APP_JWT_SECRET!) as AppUserPayload;
    req.appUser = payload;
    next();
  } catch (e: any) {
    if (e instanceof TokenExpiredError || e?.message === "jwt expired") {
      return res.status(401).json({ error: "Token expired" }); // client should call /auth/refresh
    }
    return res.status(401).json({ error: "Invalid token" });
  }
}

// For /auth/refresh: verify signature but ignore exp so we can recover sub
function getSubFromPossiblyExpiredToken(req: Request): string {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) throw new Error("Missing token");
  const payload = jwt.verify(token, APP_JWT_SECRET!, { ignoreExpiration: true }) as AppUserPayload;
  if (!payload?.sub) throw new Error("Invalid payload");
  return payload.sub;
}

// ---------- Constants ----------
const SCOPES = [
  "user-read-email",
  "user-read-currently-playing",
  "user-read-playback-state",
  "playlist-modify-private",
  "playlist-modify-public",
].join(" ");

const AUTH_URL = "https://accounts.spotify.com/authorize";
const TOKEN_URL = "https://accounts.spotify.com/api/token";

// ---------- App ----------
const app = express();

app.use(
  cors({
    origin: ALLOWED_ORIGIN.split(",").map((s) => s.trim()),
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());
// In prod you likely want this; leaving commented to avoid surprises locally
if (IS_PROD) app.set("trust proxy", 1);

app.use(
  session({
    name: "sid",
    secret: SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: IS_PROD, // set true behind HTTPS/proxy in prod
      httpOnly: true,
      sameSite: IS_PROD ? "lax" : "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// ---------- 1) Start login (PKCE) ----------
app.get("/auth/login", (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = randomState();

  // Regenerate to avoid session fixation during auth start
  req.session.regenerate((err) => {
    if (err) return res.status(500).send("Session error");
    req.session.codeVerifier = codeVerifier;
    req.session.oauthState = state;

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
});

// ---------- 2) Callback: exchange code, upsert user, sign app token ----------
app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query as { code?: string; state?: string };
    if (!code || !state) return res.status(400).send("Missing code/state");
    if (!req.session.oauthState || state !== req.session.oauthState)
      return res.status(400).send("Invalid state");
    if (!req.session.codeVerifier) return res.status(400).send("Missing PKCE code verifier");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: SPOTIFY_REDIRECT_URI!,
      client_id: SPOTIFY_CLIENT_ID!,
      code_verifier: req.session.codeVerifier,
      client_secret: SPOTIFY_CLIENT_SECRET!, // confidential client
    });

    const tokenRes = await axios.post(TOKEN_URL, body.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const { access_token, refresh_token, expires_in } = tokenRes.data as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };
    const now = Date.now();

    // Fetch profile
    const meRes = await axios.get("https://api.spotify.com/v1/me", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const me = meRes.data as {
      id: string;
      email?: string | null;
      display_name?: string | null;
      images?: Array<{ url: string }>;
    };

    // Upsert user + tokens
    await prisma.user.upsert({
      where: { id: me.id },
      update: {
        email: me.email ?? null,
        displayName: me.display_name ?? null,
        avatarUrl: me.images?.[0]?.url ?? null,
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: new Date(now + (expires_in ?? 0) * 1000),
      },
      create: {
        id: me.id,
        email: me.email ?? null,
        displayName: me.display_name ?? null,
        avatarUrl: me.images?.[0]?.url ?? null,
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: new Date(now + (expires_in ?? 0) * 1000),
      },
    });

    // Clear one-time PKCE values to prevent replay
    delete req.session.codeVerifier;
    delete req.session.oauthState;

    // Short-lived app JWT
    const appToken = signAppJWT(me.id, {
      email: me.email ?? undefined,
      name: me.display_name ?? undefined,
      scope: SCOPES,
    });

    res.redirect(`${APP_SCHEME}://auth?token=${appToken}`);
  } catch (e: any) {
    console.error("Callback error", e.response?.data || e.message);
    res.status(500).send("Auth callback failed");
  }
});

// ---------- 3) Refresh: accept expired token, refresh Spotify token, mint new app token ----------
app.post("/auth/refresh", async (req, res) => {
  try {
    const sub = getSubFromPossiblyExpiredToken(req);

    const user = await prisma.user.findUnique({ where: { id: sub } });
    if (!user?.refreshToken) return res.status(401).json({ error: "No refresh token" });

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: user.refreshToken,
      client_id: SPOTIFY_CLIENT_ID!,
      client_secret: SPOTIFY_CLIENT_SECRET!,
    });

    const tokenRes = await axios.post(TOKEN_URL, body.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      validateStatus: () => true,
    });

    if (tokenRes.status !== 200) {
      return res.status(401).json({ error: "Spotify refresh failed" });
    }

    const { access_token, expires_in, refresh_token } = tokenRes.data as {
      access_token: string;
      expires_in?: number;
      refresh_token?: string;
    };

    const updates: Record<string, any> = {
      accessToken: access_token,
      tokenExpiresAt: new Date(Date.now() + (expires_in ?? 0) * 1000),
    };
    if (refresh_token) updates.refreshToken = refresh_token; // Spotify may rotate

    const updated = await prisma.user.update({ where: { id: sub }, data: updates });

    const newAppToken = signAppJWT(sub, {
      email: updated.email ?? undefined,
      name: updated.displayName ?? undefined,
      scope: SCOPES,
    });

    res.json({ token: newAppToken });
  } catch (_e: any) {
    res.status(401).json({ error: "Refresh failed" });
  }
});

// ---------- 4) Protected APIs ----------

// Profile (from DB)
app.get("/api/me", requireAppUser, async (req, res) => {
  const sub = req.appUser!.sub;
  const user = await prisma.user.findUnique({ where: { id: sub } });
  if (!user) return res.status(401).json({ error: "User not found" });

  res.json({
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
  });
});

// Share listening session
app.post("/api/listening", requireAppUser, async (req, res) => {
  try {
    const sub = req.appUser!.sub;
    const {
      trackName,
      artistName,
      spotifyId,
      genre,
      energy,
      latitude,
      longitude,
      startedAt,
      endedAt,
      clientAt,
    } = req.body ?? {};

    if (!trackName || !artistName || !spotifyId || !startedAt || !endedAt) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const latNum =
      latitude === undefined || latitude === null || latitude === ""
        ? null
        : Number(latitude);
    const lngNum =
      longitude === undefined || longitude === null || longitude === ""
        ? null
        : Number(longitude);

    if (
      (latNum !== null && Number.isNaN(latNum)) ||
      (lngNum !== null && Number.isNaN(lngNum))
    ) {
      return res.status(400).json({ error: "Invalid latitude/longitude" });
    }

    const started = new Date(startedAt);
    const ended = new Date(endedAt);
    if (isNaN(+started) || isNaN(+ended)) {
      return res.status(400).json({ error: "Invalid startedAt/endedAt" });
    }

    const sessionRow = await prisma.listeningSession.create({
      data: {
        userId: sub,
        trackName,
        artistName,
        spotifyId,
        genre: genre ?? null,
        energy: energy != null ? Number(energy) : null,
        latitude: latNum,
        longitude: lngNum,
        startedAt: started,
        endedAt: ended,
        clientAt: clientAt ? new Date(clientAt) : new Date(),
        source: "now-playing",
      },
    });

    res.json(sessionRow);
  } catch (_e) {
    res.status(500).json({ error: "Failed to save listening session" });
  }
});

// ---- Overlap helper (fixes recursion bug) ----
function haversineMeters(lat1: number, lon1: number, lat2: number, lon2: number) {
  const R = 6371000;
  const toRad = (v: number) => (v * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

async function findOverlaps(opts: {
  sub: string;
  latNum: number;
  lngNum: number;
  radiusM: number;
  startAt: Date;
  endAt: Date;
}) {
  const { sub, latNum, lngNum, radiusM, startAt, endAt } = opts;

  const candidates = await prisma.listeningSession.findMany({
    where: {
      userId: { not: sub },
      NOT: [{ endedAt: { lte: startAt } }, { startedAt: { gte: endAt } }],
    },
    include: { user: true },
  });

  return candidates.filter((s) => {
    if (s.latitude == null || s.longitude == null) return false;
    const dist = haversineMeters(latNum, lngNum, s.latitude, s.longitude);
    return dist <= radiusM;
  });
}

// Spatio-temporal overlaps
app.get("/api/listening/overlaps", requireAppUser, async (req, res) => {
  try {
    const sub = req.appUser!.sub;
    const { lat, lng, radius = "500", start, end } = req.query;

    if (!lat || !lng || !start || !end) {
      return res.status(400).json({ error: "lat, lng, start, end required" });
    }

    const latNum = Number(lat);
    const lngNum = Number(lng);
    if (Number.isNaN(latNum) || Number.isNaN(lngNum)) {
      return res.status(400).json({ error: "Invalid lat/lng" });
    }

    const startAt = new Date(String(start));
    const endAt = new Date(String(end));
    if (isNaN(+startAt) || isNaN(+endAt)) {
      return res.status(400).json({ error: "Invalid start/end" });
    }

    const radiusM = Number(radius) || 500;

    const results = await findOverlaps({ sub, latNum, lngNum, radiusM, startAt, endAt });
    res.json(results);
  } catch (_e) {
    res.status(500).json({ error: "Failed to fetch nearby listeners" });
  }
});

// Overlaps vs your latest session (fixed: no recursion)
app.get("/api/listening/overlaps/latest", requireAppUser, async (req, res) => {
  try {
    const sub = req.appUser!.sub;
    const { lat, lng, radius = "500" } = req.query;
    if (!lat || !lng) return res.status(400).json({ error: "lat/lng required" });

    const latNum = Number(lat);
    const lngNum = Number(lng);
    if (Number.isNaN(latNum) || Number.isNaN(lngNum)) {
      return res.status(400).json({ error: "Invalid lat/lng" });
    }

    const me = await prisma.listeningSession.findFirst({
      where: { userId: sub },
      orderBy: [{ startedAt: "desc" }],
    });
    if (!me) return res.json([]);

    const results = await findOverlaps({
      sub,
      latNum,
      lngNum,
      radiusM: Number(radius) || 500,
      startAt: me.startedAt,
      endAt: me.endedAt,
    });

    res.json(results);
  } catch (_e) {
    res.status(500).json({ error: "Failed to fetch overlaps" });
  }
});

// Now playing (proxy Spotify)
app.get("/api/now-playing", requireAppUser, async (req, res) => {
  try {
    const sub = req.appUser!.sub;
    const user = await prisma.user.findUnique({ where: { id: sub } });
    if (!user?.accessToken) return res.status(401).json({ error: "No access token" });

    const spotifyRes = await axios.get("https://api.spotify.com/v1/me/player/currently-playing", {
      headers: { Authorization: `Bearer ${user.accessToken}` },
      validateStatus: () => true, // handle 204 explicitly
    });

    if (spotifyRes.status === 204) {
      return res.json({ isPlaying: false });
    }
    if (spotifyRes.status === 401) {
      // Spotify token invalid/expired (separate from app JWT) – let client trigger /auth/refresh
      return res.status(401).json({ error: "Spotify token expired" });
    }
    if (spotifyRes.status < 200 || spotifyRes.status >= 300) {
      return res.status(500).json({ error: "Spotify request failed" });
    }

    const data = spotifyRes.data;
    const item = data.item;
    const now = Date.now();

    const progressMs = data.progress_ms ?? 0;
    const durationMs = item?.duration_ms ?? 0;

    const startedAt = new Date(now - progressMs);
    const endedAt = new Date(startedAt.getTime() + durationMs);

    res.json({
      isPlaying: data.is_playing,
      spotifyId: item?.id,
      track: item?.name,
      artist: item?.artists?.map((a: any) => a.name).join(", "),
      albumArt: item?.album?.images?.[0]?.url,
      progressMs,
      durationMs,
      startedAt: startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
    });
  } catch (e: any) {
    console.error("Now playing error", e.response?.data || e.message);
    res.status(500).json({ error: "Failed to fetch now playing" });
  }
});

// ---------- Root ----------
app.get("/", (_req, res) => res.send("Spotify Auth Server running"));

// ---------- Start ----------
app.listen(Number(PORT), () => {
  console.log(`Auth server on http://127.0.0.1:${PORT}`);
});
