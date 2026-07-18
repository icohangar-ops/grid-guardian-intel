# Sentinel-OSINT

**Cyber-Physical Threat Matrix for US critical infrastructure.**
Sentinel-OSINT fuses exposed-asset discovery (Censys) with AI threat
contextualization (Tavily), MITRE ATT&CK mapping, CISA KEV enrichment,
and geo situational-awareness feeds (GDACS, NASA FIRMS, USGS, NOAA CAP)
into a single SOC-ready dossier per asset.

> "We don't just alert the operator - we turn a raw data point into
> actionable national security intelligence."

---

## Screenshots

### Threat Matrix Dashboard
![Sentinel-OSINT Threat Matrix Dashboard](/__l5e/assets-v1/83c7f29a-64b0-4f81-afc8-86034f6e7ec8/dashboard.png)

### Geo Situational Awareness Map
![Sentinel-OSINT Geo Map](/__l5e/assets-v1/0c76dca9-f756-4f0b-a35d-823e8ee79b67/map.png)

---

## What it does

- **Ingest** - Query Censys Platform API v3 for ICS/SCADA services
  (Modbus, Siemens S7, DNP3, EtherNet/IP, IEC-104, BACnet, ...) scoped
  to `location.country_code: US`, with cursor pagination. Falls back to
  a mock feed when no key is present.
- **Analyze** - Per-asset Tavily *advanced* search generates a strategic
  brief with a P1-P3 priority score, sources, MITRE ATT&CK technique
  mapping (with confidence + rationale + evidence snippets), and CISA
  KEV / NVD cross-references.
- **Geo-fuse** - A cached `GeoEvent` store aggregates:
  - **GDACS** - global disasters (wildfires, floods, storms, quakes)
  - **NASA FIRMS** - VIIRS SNPP NRT active-fire pixels, severity from FRP
  - **USGS** - earthquakes >= M4.5, past 7 days
  - **NOAA CAP** - active US weather alerts (polygon centroids)
  - **Tavily radius news sweep** - locale-scoped incident news

  Each brief shows nearby events with haversine distance + compass
  bearing, so an Ontario wildfire correctly registers as a cross-border
  threat to a Michigan grid asset.
- **Visualize** - `/map` renders Mapbox GL dark tiles with assets
  (blue squares) and geo-events colored by severity.
- **Operate** - Bulk-analyze queue with configurable exponential
  backoff + retries, snapshot diffing for watchlist deltas
  (new/closed assets), Slack/webhook notifications for P1 findings,
  ATT&CK tactics heatmap with drill-down, SOC-ready markdown/PDF
  reports, and JSON/MD/CSV evidence exports (signals + snippets).

## Tech stack

- **Framework** - TanStack Start v1 (React 19, Vite 7, Cloudflare Worker SSR)
- **Data** - TanStack Query, `createServerFn` RPC, in-worker caches
- **UI** - Tailwind v4, shadcn primitives, lucide-react
- **Map** - mapbox-gl (public token via Lovable Mapbox connector)
- **Intel** - Tavily Search API, Censys Platform API v3
- **Geo feeds** - GDACS, NASA FIRMS, USGS, NOAA (`api.weather.gov`)
- **Frameworks** - MITRE ATT&CK (ICS + Enterprise), CISA KEV, NVD

## Architecture

```text
 Censys v3  --->  listExposedAssets  --->  Threat Matrix (UI)
 ICS ports                                 filter / sort / bulk
                                                    |
                                                    v  Analyze
                                            analyzeAsset
                                            + ATT&CK map
                                            + KEV / NVD
                                            + Tavily fusion
                                                    |
                                                    v
                                            getProximityFeed  <--  GDACS
                                            (cached 15m)      <--  FIRMS
                                                              <--  USGS
                                                              <--  NOAA
                                                              <--  Tavily
                                                    |
                                                    v
                                            SOC Dossier
                                            Markdown / PDF / CSV / JSON / STIX 2.1
```

## Environment variables

Secrets live in Lovable Cloud (server-only, injected at runtime):

| Name                    | Purpose                                      | Required |
|-------------------------|----------------------------------------------|----------|
| `TAVILY_API_KEY`        | Tavily advanced search (briefs + news sweep) | Yes      |
| `CENSYS_API_KEY`        | Censys Platform API v3                       | No (mock fallback) |
| `FIRMS_MAP_KEY`         | NASA FIRMS active-fire CSV feed              | No (skips feed)    |
| `LOVABLE_API_KEY`       | Lovable connector gateway auth               | Auto     |
| `MAPBOX_API_KEY`        | Mapbox gateway (server-side)                 | Auto (connector)   |
| `VITE_LOVABLE_CONNECTOR_MAPBOX_PUBLIC_TOKEN` | Mapbox GL client token   | Auto (connector)   |

## Local development

```bash
bun install
bun dev              # vite dev server on :8080
bunx tsgo --noEmit   # typecheck
```

Routes:

| Path                    | Purpose                              |
|-------------------------|--------------------------------------|
| `/`                     | Threat matrix dashboard              |
| `/map`                  | Mapbox geo situational awareness     |
| `/asset/$ip/$port`      | Shareable stateless asset dossier    |

## Data sources & attribution

- **Censys** - https://censys.io - commercial ICS discovery
- **Tavily** - https://tavily.com - AI-native search API
- **NASA FIRMS** - https://firms.modaps.eosdis.nasa.gov - public data;
  cite as "NASA FIRMS" per their acknowledgment guidance
- **GDACS** - https://www.gdacs.org - public data
- **USGS** - https://earthquake.usgs.gov - public domain
- **NOAA / NWS** - https://api.weather.gov - public domain
- **MITRE ATT&CK** - (c) MITRE, https://attack.mitre.org
- **CISA KEV** - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **OSINT Framework** - https://github.com/lockfale/OSINT-Framework

## Security posture

- All third-party keys live server-side; no secrets shipped to the browser.
- Every server function is same-origin and gated by TanStack RPC; no
  public `/api/public/*` endpoints are exposed.
- Mapbox public token should be domain-restricted in the Mapbox dashboard.
- No PII collection; no end-user auth; watchlist state is `localStorage`-only.

## License

Proprietary - (c) Icohangar Ops. Third-party feed content retains original
licensing (public-domain USGS/NOAA, NASA FIRMS usage terms, MITRE ATT&CK
CC BY 4.0).
