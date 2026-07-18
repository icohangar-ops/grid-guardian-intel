import { createServerFn } from "@tanstack/react-start";

// ─────────────────────────────────────────────────────────────
// Geo situational-awareness feeds + Tavily radius news sweep.
// Cached GeoEvent store aggregating:
//   - GDACS   (global disasters, wildfires, storms, floods)
//   - FIRMS   (NASA active fire detections, VIIRS SNPP NRT — requires FIRMS_MAP_KEY)
//   - USGS    (earthquakes ≥ significant, past week)
//   - NOAA    (weather.gov active alerts, per US state)
// Tavily radius sweep re-uses the existing TAVILY_API_KEY secret.
// ─────────────────────────────────────────────────────────────

export type GeoEvent = {
  id: string;
  source: "gdacs" | "firms" | "usgs" | "noaa" | "tavily";
  type: string; // wildfire, flood, earthquake, storm, alert…
  title: string;
  lat?: number;
  lon?: number;
  severity: "info" | "minor" | "moderate" | "severe" | "extreme";
  startedAt?: string;
  url?: string;
  country?: string; // ISO-2
  distanceKm?: number;
  bearing?: number; // degrees from asset toward event
  snippet?: string;
};

export type ProximityFeed = {
  events: GeoEvent[];
  news: {
    title: string;
    url: string;
    snippet: string;
    publishedAt?: string;
  }[];
  center: { lat: number; lon: number } | null;
  radiusKm: number;
  fetchedAt: string;
  errors: string[];
};

const KM_PER_DEG = 111;

function haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const R = 6371;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const s =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
}

function bearingDeg(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const toDeg = (r: number) => (r * 180) / Math.PI;
  const φ1 = toRad(a.lat), φ2 = toRad(b.lat);
  const λ1 = toRad(a.lon), λ2 = toRad(b.lon);
  const y = Math.sin(λ2 - λ1) * Math.cos(φ2);
  const x =
    Math.cos(φ1) * Math.sin(φ2) -
    Math.sin(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1);
  return (toDeg(Math.atan2(y, x)) + 360) % 360;
}

// ─── GDACS ──────────────────────────────────────────────────
// EVENTS4APP returns a compact JSON list. Docs:
// https://www.gdacs.org/gdacsapi/api/events/geteventlist/EVENTS4APP
type GdacsRow = {
  eventid?: number | string;
  eventtype?: string;
  name?: string;
  eventname?: string;
  fromdate?: string;
  alertlevel?: "Green" | "Orange" | "Red";
  latitude?: number;
  longitude?: number;
  country?: string;
  countryiso3?: string;
  htmldescription?: string;
  url?: { report?: string };
};
async function fetchGdacs(): Promise<GeoEvent[]> {
  const res = await fetch(
    "https://www.gdacs.org/gdacsapi/api/events/geteventlist/EVENTS4APP",
    { headers: { "User-Agent": "sentinel-osint/1.0" } },
  );
  if (!res.ok) throw new Error(`GDACS ${res.status}`);
  const json = (await res.json()) as { features?: Array<{ properties?: GdacsRow; geometry?: { coordinates?: [number, number] } }>; events?: GdacsRow[] };
  const rows: Array<{ props: GdacsRow; coords?: [number, number] }> = [];
  if (json.features?.length) {
    for (const f of json.features) rows.push({ props: f.properties ?? {}, coords: f.geometry?.coordinates });
  } else if (Array.isArray(json.events)) {
    for (const e of json.events) rows.push({ props: e });
  }
  const severityMap: Record<string, GeoEvent["severity"]> = {
    Green: "minor",
    Orange: "moderate",
    Red: "severe",
  };
  const typeMap: Record<string, string> = {
    EQ: "earthquake",
    TC: "storm",
    FL: "flood",
    VO: "volcano",
    DR: "drought",
    WF: "wildfire",
    TS: "tsunami",
  };
  return rows.slice(0, 200).map((r): GeoEvent => {
    const p = r.props;
    const lat = p.latitude ?? r.coords?.[1];
    const lon = p.longitude ?? r.coords?.[0];
    const t = typeMap[p.eventtype ?? ""] ?? (p.eventtype ?? "event").toLowerCase();
    return {
      id: `gdacs:${p.eventid ?? p.eventname ?? Math.random()}`,
      source: "gdacs",
      type: t,
      title: p.eventname ?? p.name ?? `GDACS ${t}`,
      lat,
      lon,
      severity: severityMap[p.alertlevel ?? "Green"] ?? "info",
      startedAt: p.fromdate,
      url: p.url?.report,
      country: p.countryiso3 ?? p.country,
    };
  }).filter((e) => typeof e.lat === "number" && typeof e.lon === "number");
}

// ─── USGS earthquakes (past week, ≥ significant) ────────────
type UsgsFeature = {
  id: string;
  properties: { mag?: number; place?: string; time?: number; url?: string; alert?: string | null };
  geometry: { coordinates: [number, number, number] };
};
async function fetchUsgs(): Promise<GeoEvent[]> {
  const res = await fetch(
    "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_week.geojson",
  );
  if (!res.ok) throw new Error(`USGS ${res.status}`);
  const json = (await res.json()) as { features?: UsgsFeature[] };
  return (json.features ?? []).map((f): GeoEvent => {
    const mag = f.properties.mag ?? 0;
    const sev: GeoEvent["severity"] =
      mag >= 6.5 ? "extreme" : mag >= 5.5 ? "severe" : mag >= 4.5 ? "moderate" : "minor";
    return {
      id: `usgs:${f.id}`,
      source: "usgs",
      type: "earthquake",
      title: `M${mag.toFixed(1)} — ${f.properties.place ?? "unknown"}`,
      lat: f.geometry.coordinates[1],
      lon: f.geometry.coordinates[0],
      severity: sev,
      startedAt: f.properties.time ? new Date(f.properties.time).toISOString() : undefined,
      url: f.properties.url,
    };
  });
}

// ─── NOAA CAP alerts (US + territories) ─────────────────────
type NoaaAlert = {
  id: string;
  properties: {
    event?: string;
    headline?: string;
    severity?: string;
    sent?: string;
    areaDesc?: string;
    web?: string;
  };
  geometry?: { type: string; coordinates: unknown } | null;
};
async function fetchNoaa(): Promise<GeoEvent[]> {
  const res = await fetch(
    "https://api.weather.gov/alerts/active?status=actual&limit=200",
    { headers: { Accept: "application/geo+json", "User-Agent": "sentinel-osint (grid-monitor)" } },
  );
  if (!res.ok) throw new Error(`NOAA ${res.status}`);
  const json = (await res.json()) as { features?: NoaaAlert[] };
  const sevMap: Record<string, GeoEvent["severity"]> = {
    Extreme: "extreme",
    Severe: "severe",
    Moderate: "moderate",
    Minor: "minor",
    Unknown: "info",
  };
  const out: GeoEvent[] = [];
  for (const f of json.features ?? []) {
    let lat: number | undefined, lon: number | undefined;
    const g = f.geometry;
    if (g && g.type === "Polygon") {
      const ring = (g.coordinates as number[][][])?.[0] ?? [];
      if (ring.length) {
        // centroid approximation
        let sx = 0, sy = 0;
        for (const [x, y] of ring) { sx += x; sy += y; }
        lon = sx / ring.length;
        lat = sy / ring.length;
      }
    }
    out.push({
      id: `noaa:${f.id}`,
      source: "noaa",
      type: (f.properties.event ?? "alert").toLowerCase(),
      title: f.properties.headline ?? f.properties.event ?? "NOAA Alert",
      lat,
      lon,
      severity: sevMap[f.properties.severity ?? "Unknown"] ?? "info",
      startedAt: f.properties.sent,
      url: f.properties.web,
      country: "US",
      snippet: f.properties.areaDesc,
    });
  }
  return out;
}

// ─── NASA FIRMS active fires (VIIRS SNPP NRT, past 1 day, CONUS+) ──
// Docs: https://firms.modaps.eosdis.nasa.gov/api/area/
// CSV columns: latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,
//              satellite,instrument,confidence,version,bright_ti5,frp,daynight
// Area = west,south,east,north. Covers CONUS + AK/HI corridor + border overlap.
const FIRMS_AREA = "-172,17,-64,72";
const FIRMS_SOURCE = "VIIRS_SNPP_NRT";
const FIRMS_DAY_RANGE = 1;

async function fetchFirms(): Promise<GeoEvent[]> {
  const key = process.env.FIRMS_MAP_KEY;
  if (!key) throw new Error("FIRMS_MAP_KEY missing");
  const url = `https://firms.modaps.eosdis.nasa.gov/api/area/csv/${key}/${FIRMS_SOURCE}/${FIRMS_AREA}/${FIRMS_DAY_RANGE}`;
  const res = await fetch(url, { headers: { "User-Agent": "sentinel-osint/1.0" } });
  if (!res.ok) throw new Error(`FIRMS ${res.status}`);
  const text = await res.text();
  // FIRMS returns plaintext error bodies (e.g. "Invalid MAP_KEY") with 200 sometimes.
  if (!text.startsWith("latitude") && !text.startsWith("country_id,latitude")) {
    throw new Error(`FIRMS: ${text.slice(0, 80)}`);
  }
  const lines = text.split(/\r?\n/).filter(Boolean);
  const header = lines.shift()!.split(",");
  const idx = (k: string) => header.indexOf(k);
  const iLat = idx("latitude");
  const iLon = idx("longitude");
  const iDate = idx("acq_date");
  const iTime = idx("acq_time");
  const iConf = idx("confidence");
  const iFrp = idx("frp");
  const iSat = idx("satellite");
  const iDay = idx("daynight");
  const out: GeoEvent[] = [];
  for (const line of lines) {
    const c = line.split(",");
    const lat = Number(c[iLat]);
    const lon = Number(c[iLon]);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    const frp = Number(c[iFrp]); // fire radiative power, MW
    const conf = (c[iConf] ?? "").toLowerCase(); // n/l/h (VIIRS)
    // Severity from FRP + confidence
    let sev: GeoEvent["severity"] = "minor";
    if (frp >= 100) sev = "extreme";
    else if (frp >= 30) sev = "severe";
    else if (frp >= 10) sev = "moderate";
    else sev = conf === "h" ? "moderate" : conf === "l" ? "info" : "minor";
    const date = c[iDate];
    const time = (c[iTime] ?? "0000").padStart(4, "0");
    const startedAt = date ? `${date}T${time.slice(0, 2)}:${time.slice(2)}:00Z` : undefined;
    out.push({
      id: `firms:${date}:${time}:${lat.toFixed(3)}:${lon.toFixed(3)}`,
      source: "firms",
      type: "wildfire",
      title: `Active fire · ${Number.isFinite(frp) ? `${frp.toFixed(1)} MW` : "FRP n/a"} (${c[iSat] ?? "VIIRS"} ${c[iDay] ?? ""})`.trim(),
      lat,
      lon,
      severity: sev,
      startedAt,
      url: `https://firms.modaps.eosdis.nasa.gov/map/#d:${date};@${lon.toFixed(2)},${lat.toFixed(2)},9z`,
      snippet: `Confidence: ${conf || "n/a"} · FRP: ${Number.isFinite(frp) ? frp.toFixed(1) : "n/a"} MW`,
    });
  }
  // FIRMS can return thousands of pixels; sort by FRP-derived severity and cap.
  const sevRank: Record<GeoEvent["severity"], number> = { extreme: 4, severe: 3, moderate: 2, minor: 1, info: 0 };
  out.sort((a, b) => sevRank[b.severity] - sevRank[a.severity]);
  return out.slice(0, 500);
}

// ─── In-memory cache (per worker instance) ──────────────────
type CacheEntry = { at: number; events: GeoEvent[] };
const CACHE: Record<string, CacheEntry> = {};
const TTL_MS = 15 * 60 * 1000;

type FeedName = "gdacs" | "firms" | "usgs" | "noaa";
async function loadFeed(name: FeedName): Promise<{ events: GeoEvent[]; error?: string }> {
  const cached = CACHE[name];
  if (cached && Date.now() - cached.at < TTL_MS) return { events: cached.events };
  try {
    const events =
      name === "gdacs" ? await fetchGdacs()
      : name === "firms" ? await fetchFirms()
      : name === "usgs" ? await fetchUsgs()
      : await fetchNoaa();
    CACHE[name] = { at: Date.now(), events };
    return { events };
  } catch (err) {
    // Serve stale on failure if we have anything cached.
    if (cached) return { events: cached.events, error: `${name}: ${(err as Error).message} (stale)` };
    return { events: [], error: `${name}: ${(err as Error).message}` };
  }
}

async function loadAllFeeds(): Promise<{ events: GeoEvent[]; errors: string[] }> {
  const [g, f, u, n] = await Promise.all([
    loadFeed("gdacs"),
    loadFeed("firms"),
    loadFeed("usgs"),
    loadFeed("noaa"),
  ]);
  const errors = [g.error, f.error, u.error, n.error].filter(Boolean) as string[];
  return { events: [...g.events, ...f.events, ...u.events, ...n.events], errors };
}

// ─── Tavily radius news sweep ───────────────────────────────
async function tavilyRadiusNews(
  where: string,
  radiusKm: number,
): Promise<{ items: ProximityFeed["news"]; error?: string }> {
  const key = process.env.TAVILY_API_KEY;
  if (!key) return { items: [], error: "TAVILY_API_KEY missing" };
  const query =
    `Recent (past 14 days) incidents within ~${radiusKm} km of ${where}: ` +
    `wildfires, floods, evacuations, power outages, cyber intrusions, ` +
    `pipeline/rail sabotage, civil unrest, or infrastructure threats that ` +
    `could impact grid, water, oil & gas, or telecom operations. Include ` +
    `cross-border events from Canada or Mexico when close to the border.`;
  try {
    const res = await fetch("https://api.tavily.com/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        api_key: key,
        query,
        search_depth: "advanced",
        include_answer: false,
        max_results: 8,
        topic: "news",
        days: 14,
      }),
    });
    if (!res.ok) return { items: [], error: `Tavily ${res.status}` };
    const json = (await res.json()) as {
      results?: Array<{ title?: string; url?: string; content?: string; published_date?: string }>;
    };
    return {
      items: (json.results ?? []).map((r) => ({
        title: r.title ?? r.url ?? "Untitled",
        url: r.url ?? "",
        snippet: (r.content ?? "").slice(0, 400),
        publishedAt: r.published_date,
      })),
    };
  } catch (err) {
    return { items: [], error: (err as Error).message };
  }
}

// ─── Public server functions ────────────────────────────────

export const getProximityFeed = createServerFn({ method: "POST" })
  .inputValidator(
    (input: {
      lat?: number;
      lon?: number;
      radiusKm?: number;
      location?: string; // for Tavily sweep when coords unknown
      includeNews?: boolean;
    }) => input,
  )
  .handler(async ({ data }): Promise<ProximityFeed> => {
    const radiusKm = Math.max(25, Math.min(1500, data.radiusKm ?? 300));
    const center =
      typeof data.lat === "number" && typeof data.lon === "number"
        ? { lat: data.lat, lon: data.lon }
        : null;
    const { events: allEvents, errors } = await loadAllFeeds();
    let events: GeoEvent[] = allEvents;

    if (center) {
      // Include neighboring CA/MX events within radius (auto — no country filter).
      // Quick bbox prefilter, then haversine.
      const degPad = (radiusKm / KM_PER_DEG) + 1;
      events = events
        .filter((e) => typeof e.lat === "number" && typeof e.lon === "number")
        .filter(
          (e) =>
            Math.abs((e.lat as number) - center.lat) <= degPad &&
            Math.abs((e.lon as number) - center.lon) <= degPad,
        )
        .map((e) => {
          const p = { lat: e.lat as number, lon: e.lon as number };
          const d = haversineKm(center, p);
          return { ...e, distanceKm: d, bearing: bearingDeg(center, p) };
        })
        .filter((e) => (e.distanceKm ?? Infinity) <= radiusKm)
        .sort((a, b) => (a.distanceKm ?? 0) - (b.distanceKm ?? 0));
    } else {
      // No coords — return most recent globally significant events (cap 40)
      events = events
        .sort((a, b) => new Date(b.startedAt ?? 0).getTime() - new Date(a.startedAt ?? 0).getTime())
        .slice(0, 40);
    }

    let news: ProximityFeed["news"] = [];
    if (data.includeNews !== false) {
      const where = data.location?.trim() || (center ? `${center.lat.toFixed(2)},${center.lon.toFixed(2)}` : "United States critical infrastructure");
      const nres = await tavilyRadiusNews(where, radiusKm);
      news = nres.items;
      if (nres.error) errors.push(nres.error);
    }

    return {
      events: events.slice(0, 40),
      news,
      center,
      radiusKm,
      fetchedAt: new Date().toISOString(),
      errors,
    };
  });

// Un-scoped variant: pull all events for the map view.
export const getGlobalGeoEvents = createServerFn({ method: "GET" }).handler(
  async (): Promise<{ events: GeoEvent[]; errors: string[]; fetchedAt: string }> => {
    const { events: allEvents, errors } = await loadAllFeeds();
    // Prioritize higher-severity + newer events; cap for wire size.
    const rank: Record<GeoEvent["severity"], number> = { extreme: 4, severe: 3, moderate: 2, minor: 1, info: 0 };
    const events = allEvents
      .filter((e) => typeof e.lat === "number" && typeof e.lon === "number")
      .sort((a, b) => {
        const r = (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0);
        if (r) return r;
        return new Date(b.startedAt ?? 0).getTime() - new Date(a.startedAt ?? 0).getTime();
      })
      .slice(0, 300);
    return { events, errors, fetchedAt: new Date().toISOString() };
  },
);