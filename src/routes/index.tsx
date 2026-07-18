import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { queryOptions, useSuspenseQuery, useMutation, useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Star, ArrowUpDown, ExternalLink, Bell, Download, Radar } from "lucide-react";
import {
  listExposedAssets,
  analyzeAsset,
  getReconToolkit,
  getKevForProtocols,
  sendWebhook,
  type ThreatBrief,
  type OsintAsset,
  type ReconToolkit,
  type KevReport,
} from "@/lib/sentinel.functions";
import {
  loadBriefs,
  saveBrief,
  loadWatch,
  toggleWatch,
  loadSnapshot,
  saveSnapshot,
  diffSnapshot,
  loadAudit,
  logAudit,
  loadWebhook,
  saveWebhook,
  type AuditEvent,
  type WebhookConfig,
} from "@/lib/sentinel-storage";
import { assetsToCsv, assetsToStix, downloadText } from "@/lib/sentinel-export";

const assetsQuery = (query?: string, cursor?: string) =>
  queryOptions({
    queryKey: ["sentinel", "assets", query ?? "", cursor ?? ""],
    queryFn: () => listExposedAssets({ data: { query, cursor } }),
  });

type SortKey = "priority" | "port" | "org" | "analyzed";
type ColumnKey = "target" | "protocol" | "location" | "kev" | "priority" | "analyzed";
const DEFAULT_COLUMNS: Record<ColumnKey, boolean> = {
  target: true,
  protocol: true,
  location: true,
  kev: true,
  priority: true,
  analyzed: true,
};
const PRIORITY_RANK: Record<string, number> = {
  "P1 - CRITICAL": 0,
  "P2 - HIGH": 1,
  "P3 - MONITOR": 2,
};

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Sentinel-OSINT — Cyber-Physical Threat Prioritization" },
      {
        name: "description",
        content:
          "Fuses infrastructure OSINT with Tavily AI-synthesized geopolitical and cyber-threat intelligence to prioritize alerts for critical infrastructure defenders.",
      },
      { property: "og:title", content: "Sentinel-OSINT — Threat Matrix" },
      {
        property: "og:description",
        content:
          "From raw exposed-asset data to actionable national security intelligence.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(assetsQuery()),
  component: SentinelDashboard,
});

function SentinelDashboard() {
  const [query, setQuery] = useState<string>("");
  const [activeQuery, setActiveQuery] = useState<string>("");
  // Stack of cursors; index 0 = undefined (first page). Length - 1 is current page.
  const [cursorStack, setCursorStack] = useState<(string | undefined)[]>([undefined]);
  const currentCursor = cursorStack[cursorStack.length - 1];
  const pageIndex = cursorStack.length - 1;
  const { data: feed, isFetching, refetch } = useSuspenseQuery(
    assetsQuery(activeQuery, currentCursor),
  );
  const analyzeFn = useServerFn(analyzeAsset);
  const reconFn = useServerFn(getReconToolkit);
  const kevFn = useServerFn(getKevForProtocols);
  const webhookFn = useServerFn(sendWebhook);
  // Briefs are keyed by asset.id (ip:port), so mapping survives across pages.
  const [briefs, setBriefs] = useState<Record<string, ThreatBrief>>({});
  const [toolkits, setToolkits] = useState<Record<string, ReconToolkit>>({});
  const [selected, setSelected] = useState<string | null>(null);

  // Persisted state hydration.
  const [watch, setWatch] = useState<Record<string, { asset: OsintAsset; addedAt: string }>>({});
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [webhook, setWebhook] = useState<WebhookConfig>({ url: "", enabled: false });
  const [delta, setDelta] = useState<{ added: string[]; closed: string[] } | null>(null);
  useEffect(() => {
    setBriefs(loadBriefs());
    setWatch(loadWatch());
    setAudit(loadAudit());
    setWebhook(loadWebhook());
  }, []);

  // Filters + sort + column state.
  const [search, setSearch] = useState("");
  const [sectorFilter, setSectorFilter] = useState<string>("all");
  const [protoFilter, setProtoFilter] = useState<string>("all");
  const [priorityFilter, setPriorityFilter] = useState<string>("all");
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({
    key: "priority",
    dir: "asc",
  });
  const [columns, setColumns] = useState<Record<ColumnKey, boolean>>(DEFAULT_COLUMNS);

  // Bulk analyze queue: per-asset status with retry metadata.
  type BulkState =
    | { status: "queued" }
    | { status: "running"; attempt: number }
    | { status: "retrying"; attempt: number; nextInMs: number; lastError: string }
    | { status: "done" }
    | { status: "error"; attempts: number; reason: string };
  const [bulkStatus, setBulkStatus] = useState<Record<string, BulkState>>({});
  const bulkRunning = useRef(false);

  // Bulk retry configuration (persisted).
  const [retryConfig, setRetryConfig] = useState<{ attempts: number; baseMs: number }>(() => {
    if (typeof window === "undefined") return { attempts: 4, baseMs: 800 };
    try {
      const raw = localStorage.getItem("sentinel:bulk-retry");
      if (raw) {
        const p = JSON.parse(raw);
        const attempts = Math.max(1, Math.min(10, Number(p.attempts) || 4));
        const baseMs = Math.max(100, Math.min(10000, Number(p.baseMs) || 800));
        return { attempts, baseMs };
      }
    } catch { /* ignore */ }
    return { attempts: 4, baseMs: 800 };
  });
  useEffect(() => {
    try { localStorage.setItem("sentinel:bulk-retry", JSON.stringify(retryConfig)); } catch { /* ignore */ }
  }, [retryConfig]);

  // KEV enrichment: proto → matches[]
  const protoList = useMemo(
    () => Array.from(new Set(feed.assets.map((a) => a.protocol))),
    [feed.assets],
  );
  const kevQuery = useQuery({
    queryKey: ["sentinel", "kev", protoList.sort().join("|")],
    queryFn: () => kevFn({ data: { protocols: protoList } }),
    enabled: protoList.length > 0,
    staleTime: 60 * 60 * 1000,
  });
  const kev: KevReport = kevQuery.data ?? {};

  const mutation = useMutation({
    mutationFn: (asset: OsintAsset) => analyzeFn({ data: { asset } }),
    onSuccess: (brief) => {
      handleBrief(brief);
      setSelected(brief.asset.id);
    },
  });

  const handleBrief = useCallback(
    (brief: ThreatBrief) => {
      setBriefs((prev) => ({ ...prev, [brief.asset.id]: brief }));
      saveBrief(brief);
      logAudit({
        assetId: brief.asset.id,
        kind: "analyze",
        detail: `${brief.priority} — ${brief.asset.protocol} @ ${brief.asset.location}`,
      });
      setAudit(loadAudit());
      if (brief.priority === "P1 - CRITICAL" && webhook.enabled && webhook.url) {
        webhookFn({
          data: {
            url: webhook.url,
            payload: {
              text: `:rotating_light: Sentinel P1 — ${brief.asset.ip}:${brief.asset.port} (${brief.asset.protocol}) — ${brief.asset.org} @ ${brief.asset.location}`,
              brief: {
                asset: brief.asset,
                priority: brief.priority,
                summary: brief.summary,
                sources: brief.sources,
              },
            },
          },
        }).catch(() => {/* swallow; UI already reflects the brief */});
      }
    },
    [webhook, webhookFn],
  );

  const reconMutation = useMutation({
    mutationFn: (asset: OsintAsset) => reconFn({ data: { asset } }),
    onSuccess: (kit) => {
      setToolkits((prev) => ({ ...prev, [kit.asset.id]: kit }));
    },
  });

  const resetPagination = () => setCursorStack([undefined]);
  const goNext = () => {
    if (feed.nextCursor) setCursorStack((s) => [...s, feed.nextCursor]);
  };
  const goPrev = () => {
    if (cursorStack.length > 1) setCursorStack((s) => s.slice(0, -1));
  };

  // Filter + sort pipeline.
  const sectorOptions = useMemo(
    () => ["all", ...Array.from(new Set(feed.assets.map((a) => a.sector)))],
    [feed.assets],
  );
  const protoOptions = useMemo(
    () => ["all", ...Array.from(new Set(feed.assets.map((a) => a.protocol)))],
    [feed.assets],
  );

  const visibleAssets = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = feed.assets.filter((a) => {
      if (sectorFilter !== "all" && a.sector !== sectorFilter) return false;
      if (protoFilter !== "all" && a.protocol !== protoFilter) return false;
      if (priorityFilter !== "all") {
        const p: string = briefs[a.id]?.priority ?? "UNSCORED";
        if (priorityFilter === "unscored" ? p !== "UNSCORED" : p !== priorityFilter)
          return false;
      }
      if (!q) return true;
      return (
        a.ip.includes(q) ||
        a.org.toLowerCase().includes(q) ||
        a.location.toLowerCase().includes(q) ||
        a.protocol.toLowerCase().includes(q) ||
        a.sector.toLowerCase().includes(q) ||
        String(a.port).includes(q)
      );
    });
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => {
      if (sort.key === "port") return (a.port - b.port) * dir;
      if (sort.key === "org") return a.org.localeCompare(b.org) * dir;
      if (sort.key === "analyzed") {
        const ta = briefs[a.id]?.generatedAt ?? "";
        const tb = briefs[b.id]?.generatedAt ?? "";
        return ta.localeCompare(tb) * dir;
      }
      // priority
      const pa = PRIORITY_RANK[briefs[a.id]?.priority ?? ""] ?? 99;
      const pb = PRIORITY_RANK[briefs[b.id]?.priority ?? ""] ?? 99;
      return (pa - pb) * dir;
    });
  }, [feed.assets, search, sectorFilter, protoFilter, priorityFilter, sort, briefs]);

  const toggleSort = (key: SortKey) =>
    setSort((s) =>
      s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" },
    );

  // Bulk analyze visible rows with exponential backoff retry.
  const runBulk = async () => {
    if (bulkRunning.current) return;
    bulkRunning.current = true;
    const queue = visibleAssets.filter((a) => !briefs[a.id]);
    setBulkStatus(
      Object.fromEntries(queue.map((a) => [a.id, { status: "queued" } as BulkState])),
    );
    const MAX_ATTEMPTS = retryConfig.attempts;
    const BASE_MS = retryConfig.baseMs;
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const errMsg = (e: unknown) => {
      if (e instanceof Error) return e.message || e.name;
      if (typeof e === "string") return e;
      try { return JSON.stringify(e); } catch { return "unknown error"; }
    };
    for (const asset of queue) {
      let lastErr = "unknown error";
      let success = false;
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        setBulkStatus((s) => ({ ...s, [asset.id]: { status: "running", attempt } }));
        try {
          const brief = await analyzeFn({ data: { asset } });
          handleBrief(brief);
          setBulkStatus((s) => ({ ...s, [asset.id]: { status: "done" } }));
          success = true;
          break;
        } catch (e) {
          lastErr = errMsg(e);
          if (attempt < MAX_ATTEMPTS) {
            // Exponential backoff with jitter: 800, 1600, 3200 ms (+/- 25%).
            const base = BASE_MS * 2 ** (attempt - 1);
            const jitter = base * (Math.random() * 0.5 - 0.25);
            const wait = Math.round(base + jitter);
            setBulkStatus((s) => ({
              ...s,
              [asset.id]: { status: "retrying", attempt, nextInMs: wait, lastError: lastErr },
            }));
            await sleep(wait);
          }
        }
      }
      if (!success) {
        setBulkStatus((s) => ({
          ...s,
          [asset.id]: { status: "error", attempts: MAX_ATTEMPTS, reason: lastErr },
        }));
      }
    }
    bulkRunning.current = false;
  };

  // Re-poll + diff.
  const rePoll = async () => {
    const key = activeQuery || "__default__";
    const prev = loadSnapshot(key);
    await refetch();
    // feed will update after refetch; compute diff from latest data in next tick.
    setTimeout(() => {
      const ids = feed.assets.map((a) => a.id);
      const d = diffSnapshot(prev, ids);
      saveSnapshot(key, ids);
      if (!d.first) {
        setDelta({ added: d.added, closed: d.closed });
        if (d.added.length || d.closed.length) {
          logAudit({
            assetId: "*",
            kind: "delta",
            detail: `+${d.added.length} / -${d.closed.length} on query "${key}"`,
          });
          setAudit(loadAudit());
        }
      } else {
        setDelta(null);
      }
    }, 200);
  };

  // Watchlist toggle.
  const onToggleWatch = (asset: OsintAsset) => {
    const nowWatched = toggleWatch(asset);
    setWatch(loadWatch());
    logAudit({
      assetId: asset.id,
      kind: nowWatched ? "watch" : "unwatch",
      detail: `${asset.ip}:${asset.port}`,
    });
    setAudit(loadAudit());
  };

  // Exports.
  const exportCsv = () =>
    downloadText(
      `sentinel-${Date.now()}.csv`,
      "text/csv",
      assetsToCsv(visibleAssets, briefs),
    );
  const exportStix = () =>
    downloadText(
      `sentinel-${Date.now()}.stix.json`,
      "application/json",
      assetsToStix(visibleAssets, briefs),
    );

  // Geo heatmap counts (state → n).
  const stateCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const a of feed.assets) {
      const s = a.province || parseState(a.location);
      if (!s) continue;
      map.set(s, (map.get(s) ?? 0) + 1);
    }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [feed.assets]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border">
        <div className="mx-auto max-w-7xl px-6 py-8">
          <div className="flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-destructive animate-pulse" />
            <span className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Sentinel-OSINT // US Homeland Scope
            </span>
          </div>
          <h1 className="mt-3 text-4xl font-bold tracking-tight">
            Cyber-Physical Threat Matrix
          </h1>
          <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
            Ingests exposed critical infrastructure assets and fuses them with Tavily
            AI-synthesized intelligence — turning raw OSINT into prioritized national
            security context.
          </p>
        </div>
      </header>

      <main className="mx-auto grid max-w-7xl gap-6 px-6 py-8 lg:grid-cols-[1.4fr_1fr]">
        <section>
          <div className="mb-3 flex items-center justify-between gap-3">
            <h2 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Exposed Assets ({visibleAssets.length}/{feed.assets.length}) ·{" "}
              <span
                className={
                  feed.source === "censys"
                    ? "text-chart-2"
                    : "text-chart-4"
                }
              >
                {feed.source === "censys" ? "LIVE / CENSYS" : "MOCK FEED"}
              </span>
            </h2>
            <div className="flex items-center gap-2">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    resetPagination();
                    setActiveQuery(query);
                  }
                }}
                placeholder="Censys query (e.g. services.port: 502)"
                className="w-72 rounded-md border border-border bg-background px-3 py-1.5 font-mono text-xs"
              />
              <button
                onClick={() => {
                  resetPagination();
                  setActiveQuery(query);
                  refetch();
                }}
                disabled={isFetching}
                className="rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
              >
                {isFetching ? "Querying…" : "Ingest"}
              </button>
            </div>
          </div>
          {feed.error && (
            <div className="mb-3 rounded-md border border-chart-4/40 bg-chart-4/10 px-3 py-2 text-xs text-chart-4">
              {feed.error}
            </div>
          )}
          {delta && (delta.added.length > 0 || delta.closed.length > 0) && (
            <div className="mb-3 rounded-md border border-primary/40 bg-primary/10 px-3 py-2 text-xs">
              <span className="font-mono uppercase text-primary">Δ delta</span> ·{" "}
              <span className="text-chart-2">+{delta.added.length} new</span>{" "}
              <span className="text-muted-foreground">/</span>{" "}
              <span className="text-chart-4">-{delta.closed.length} closed</span> since
              last snapshot
            </div>
          )}

          <ToolbarPanel
            search={search}
            setSearch={setSearch}
            sectorOptions={sectorOptions}
            sector={sectorFilter}
            setSector={setSectorFilter}
            protoOptions={protoOptions}
            proto={protoFilter}
            setProto={setProtoFilter}
            priority={priorityFilter}
            setPriority={setPriorityFilter}
            columns={columns}
            setColumns={setColumns}
            onBulk={runBulk}
            onRePoll={rePoll}
            onCsv={exportCsv}
            onStix={exportStix}
            bulkPending={Object.values(bulkStatus).some(
              (s) => s.status === "queued" || s.status === "running" || s.status === "retrying",
            )}
            retryConfig={retryConfig}
            setRetryConfig={setRetryConfig}
          />

          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs uppercase text-muted-foreground">
                <tr>
                  {columns.target && (
                    <th className="px-3 py-2 text-left font-medium">
                      <SortHeader label="Target / Org" onClick={() => toggleSort("org")} active={sort.key === "org"} dir={sort.dir} />
                    </th>
                  )}
                  {columns.protocol && (
                    <th className="px-3 py-2 text-left font-medium">
                      <SortHeader label="Protocol / Port" onClick={() => toggleSort("port")} active={sort.key === "port"} dir={sort.dir} />
                    </th>
                  )}
                  {columns.location && (
                    <th className="px-3 py-2 text-left font-medium">Location</th>
                  )}
                  {columns.kev && (
                    <th className="px-3 py-2 text-left font-medium">KEV</th>
                  )}
                  {columns.priority && (
                    <th className="px-3 py-2 text-left font-medium">
                      <SortHeader label="Priority" onClick={() => toggleSort("priority")} active={sort.key === "priority"} dir={sort.dir} />
                    </th>
                  )}
                  {columns.analyzed && (
                    <th className="px-3 py-2 text-left font-medium">
                      <SortHeader label="Analyzed" onClick={() => toggleSort("analyzed")} active={sort.key === "analyzed"} dir={sort.dir} />
                    </th>
                  )}
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {visibleAssets.map((asset) => (
                  <AssetRow
                    key={asset.id}
                    asset={asset}
                    brief={briefs[asset.id]}
                    selected={selected === asset.id}
                    loading={mutation.isPending && mutation.variables?.id === asset.id}
                    bulk={bulkStatus[asset.id]}
                    watched={Boolean(watch[asset.id])}
                    kevCount={kev[asset.protocol]?.length ?? 0}
                    columns={columns}
                    onAnalyze={() => mutation.mutate(asset)}
                    onSelect={() => setSelected(asset.id)}
                    onToggleWatch={() => onToggleWatch(asset)}
                  />
                ))}
                {visibleAssets.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-3 py-6 text-center text-xs text-muted-foreground">
                      No assets match your filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs">
            <span className="font-mono text-muted-foreground">
              Page {pageIndex + 1} · {feed.assets.length} rows ·{" "}
              {Object.keys(briefs).length} briefs cached
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={goPrev}
                disabled={pageIndex === 0 || isFetching}
                className="rounded-md border border-border bg-background px-3 py-1.5 font-medium hover:bg-accent disabled:opacity-40"
              >
                ← Prev
              </button>
              <button
                onClick={goNext}
                disabled={!feed.nextCursor || isFetching}
                className="rounded-md border border-border bg-background px-3 py-1.5 font-medium hover:bg-accent disabled:opacity-40"
              >
                {isFetching ? "Loading…" : "Next →"}
              </button>
            </div>
          </div>

          <GeoHeatmap counts={stateCounts} />
        </section>

        <aside>
          <h2 className="mb-3 text-xs font-mono uppercase tracking-widest text-muted-foreground">
            Threat Brief
          </h2>
          <BriefPanel
            brief={selected ? briefs[selected] : undefined}
            asset={selected ? feed.assets.find((a) => a.id === selected) : undefined}
            error={mutation.error?.message}
            kev={selected ? kev[feed.assets.find((a) => a.id === selected)?.protocol ?? ""] : undefined}
          />
          <NotifierPanel webhook={webhook} setWebhook={(w) => { saveWebhook(w); setWebhook(w); }} />
          <WatchlistPanel watch={watch} briefs={briefs} onOpen={(id) => setSelected(id)} />
          <AuditPanel events={audit} />
          <h2 className="mb-3 mt-6 text-xs font-mono uppercase tracking-widest text-muted-foreground">
            Recon Toolkit · OSINT Framework
          </h2>
          <ToolkitPanel
            asset={selected ? feed.assets.find((a) => a.id === selected) : undefined}
            toolkit={selected ? toolkits[selected] : undefined}
            loading={reconMutation.isPending}
            error={reconMutation.error?.message}
            onLoad={(asset: OsintAsset) => reconMutation.mutate(asset)}
          />
        </aside>
      </main>
    </div>
  );
}

// ─── US state parsing (fallback when Censys province is absent) ───
const US_STATES: Record<string, string> = {
  Alabama: "AL", Alaska: "AK", Arizona: "AZ", Arkansas: "AR", California: "CA",
  Colorado: "CO", Connecticut: "CT", Delaware: "DE", Florida: "FL", Georgia: "GA",
  Hawaii: "HI", Idaho: "ID", Illinois: "IL", Indiana: "IN", Iowa: "IA",
  Kansas: "KS", Kentucky: "KY", Louisiana: "LA", Maine: "ME", Maryland: "MD",
  Massachusetts: "MA", Michigan: "MI", Minnesota: "MN", Mississippi: "MS",
  Missouri: "MO", Montana: "MT", Nebraska: "NE", Nevada: "NV",
  "New Hampshire": "NH", "New Jersey": "NJ", "New Mexico": "NM", "New York": "NY",
  "North Carolina": "NC", "North Dakota": "ND", Ohio: "OH", Oklahoma: "OK",
  Oregon: "OR", Pennsylvania: "PA", "Rhode Island": "RI", "South Carolina": "SC",
  "South Dakota": "SD", Tennessee: "TN", Texas: "TX", Utah: "UT", Vermont: "VT",
  Virginia: "VA", Washington: "WA", "West Virginia": "WV", Wisconsin: "WI",
  Wyoming: "WY", "District of Columbia": "DC",
};
function parseState(location: string): string | null {
  for (const name of Object.keys(US_STATES)) {
    if (location.includes(name)) return name;
  }
  return null;
}

// ─── Toolbar (search, filters, sort, bulk, export, columns) ──────
function ToolbarPanel(props: {
  search: string;
  setSearch: (s: string) => void;
  sectorOptions: string[];
  sector: string;
  setSector: (s: string) => void;
  protoOptions: string[];
  proto: string;
  setProto: (s: string) => void;
  priority: string;
  setPriority: (s: string) => void;
  columns: Record<ColumnKey, boolean>;
  setColumns: (c: Record<ColumnKey, boolean>) => void;
  onBulk: () => void;
  onRePoll: () => void;
  onCsv: () => void;
  onStix: () => void;
  bulkPending: boolean;
  retryConfig: { attempts: number; baseMs: number };
  setRetryConfig: (c: { attempts: number; baseMs: number }) => void;
}) {
  const [showCols, setShowCols] = useState(false);
  const rc = props.retryConfig;
  const maxDelaySec = Math.round((rc.baseMs * 2 ** (rc.attempts - 2)) / 100) / 10;
  return (
    <div className="mb-3 space-y-2 rounded-md border border-border bg-card p-3">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={props.search}
          onChange={(e) => props.setSearch(e.target.value)}
          placeholder="Search IP, org, location, protocol, sector…"
          className="min-w-[220px] flex-1 rounded-md border border-border bg-background px-3 py-1.5 font-mono text-xs"
        />
        <select
          value={props.sector}
          onChange={(e) => props.setSector(e.target.value)}
          className="rounded-md border border-border bg-background px-2 py-1.5 text-xs"
        >
          {props.sectorOptions.map((s) => (
            <option key={s} value={s}>{s === "all" ? "All sectors" : s}</option>
          ))}
        </select>
        <select
          value={props.proto}
          onChange={(e) => props.setProto(e.target.value)}
          className="rounded-md border border-border bg-background px-2 py-1.5 text-xs"
        >
          {props.protoOptions.map((s) => (
            <option key={s} value={s}>{s === "all" ? "All protocols" : s}</option>
          ))}
        </select>
        <select
          value={props.priority}
          onChange={(e) => props.setPriority(e.target.value)}
          className="rounded-md border border-border bg-background px-2 py-1.5 text-xs"
        >
          <option value="all">All priorities</option>
          <option value="P1 - CRITICAL">P1 Critical</option>
          <option value="P2 - HIGH">P2 High</option>
          <option value="P3 - MONITOR">P3 Monitor</option>
          <option value="unscored">Unscored</option>
        </select>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <button
          onClick={props.onBulk}
          disabled={props.bulkPending}
          className="rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 font-medium text-primary hover:bg-primary/20 disabled:opacity-50"
        >
          {props.bulkPending ? "Analyzing visible…" : "Bulk analyze visible"}
        </button>
        <div
          className="inline-flex items-center gap-2 rounded-md border border-border bg-background px-2 py-1 font-mono text-[11px] text-muted-foreground"
          title={`Per row: up to ${rc.attempts} attempts with exponential backoff starting at ${rc.baseMs}ms (max wait before last retry ≈ ${maxDelaySec}s).`}
        >
          <label className="flex items-center gap-1">
            <span className="uppercase tracking-wider">Retries</span>
            <input
              type="number"
              min={1}
              max={10}
              value={rc.attempts}
              disabled={props.bulkPending}
              onChange={(e) =>
                props.setRetryConfig({
                  ...rc,
                  attempts: Math.max(1, Math.min(10, Number(e.target.value) || 1)),
                })
              }
              className="w-12 rounded border border-border bg-card px-1 py-0.5 text-right text-foreground disabled:opacity-50"
            />
          </label>
          <span className="text-border">·</span>
          <label className="flex items-center gap-1">
            <span className="uppercase tracking-wider">Backoff</span>
            <input
              type="number"
              min={100}
              max={10000}
              step={100}
              value={rc.baseMs}
              disabled={props.bulkPending}
              onChange={(e) =>
                props.setRetryConfig({
                  ...rc,
                  baseMs: Math.max(100, Math.min(10000, Number(e.target.value) || 100)),
                })
              }
              className="w-16 rounded border border-border bg-card px-1 py-0.5 text-right text-foreground disabled:opacity-50"
            />
            <span>ms</span>
          </label>
        </div>
        <button
          onClick={props.onRePoll}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 hover:bg-accent"
        >
          <Radar size={12} /> Re-poll + diff
        </button>
        <button
          onClick={props.onCsv}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 hover:bg-accent"
        >
          <Download size={12} /> CSV
        </button>
        <button
          onClick={props.onStix}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 hover:bg-accent"
        >
          <Download size={12} /> STIX 2.1
        </button>
        <button
          onClick={() => setShowCols((v) => !v)}
          className="ml-auto rounded-md border border-border bg-background px-3 py-1.5 hover:bg-accent"
        >
          Columns
        </button>
      </div>
      {showCols && (
        <div className="flex flex-wrap gap-2 border-t border-border pt-2 text-xs">
          {(Object.keys(props.columns) as ColumnKey[]).map((k) => (
            <label key={k} className="flex items-center gap-1 font-mono uppercase text-muted-foreground">
              <input
                type="checkbox"
                checked={props.columns[k]}
                onChange={(e) =>
                  props.setColumns({ ...props.columns, [k]: e.target.checked })
                }
              />
              {k}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

function SortHeader({
  label, onClick, active, dir,
}: { label: string; onClick: () => void; active: boolean; dir: "asc" | "desc" }) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1 hover:text-foreground ${active ? "text-foreground" : ""}`}
    >
      {label}
      <ArrowUpDown size={10} />
      {active && <span className="text-[9px]">{dir}</span>}
    </button>
  );
}

// ─── US state heatmap (bar list) ──────────────────────────────
function GeoHeatmap({ counts }: { counts: [string, number][] }) {
  if (!counts.length) return null;
  const max = counts[0][1];
  return (
    <div className="mt-6 rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-xs font-mono uppercase tracking-widest text-muted-foreground">
        Geo Heatmap — Exposed Assets by US State
      </h3>
      <ul className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
        {counts.slice(0, 20).map(([state, n]) => (
          <li key={state} className="flex items-center gap-2 text-xs">
            <span className="w-32 shrink-0 truncate font-mono text-muted-foreground">
              {US_STATES[state] ?? "??"} · {state}
            </span>
            <div className="relative h-4 flex-1 overflow-hidden rounded bg-muted">
              <div
                className="h-full bg-destructive/70"
                style={{ width: `${(n / max) * 100}%` }}
              />
            </div>
            <span className="w-8 shrink-0 text-right font-mono tabular-nums text-foreground">
              {n}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ─── Notifier config ──────────────────────────────────────────
function NotifierPanel({
  webhook, setWebhook,
}: { webhook: WebhookConfig; setWebhook: (w: WebhookConfig) => void }) {
  const [url, setUrl] = useState(webhook.url);
  useEffect(() => setUrl(webhook.url), [webhook.url]);
  return (
    <div className="mt-6 rounded-lg border border-border bg-card p-4">
      <h3 className="mb-2 flex items-center gap-2 text-xs font-mono uppercase tracking-widest text-muted-foreground">
        <Bell size={12} /> P1 Notifier · Slack / Webhook
      </h3>
      <input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        onBlur={() => setWebhook({ ...webhook, url })}
        placeholder="https://hooks.slack.com/services/..."
        className="w-full rounded-md border border-border bg-background px-3 py-1.5 font-mono text-xs"
      />
      <label className="mt-2 flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          checked={webhook.enabled}
          onChange={(e) => setWebhook({ url, enabled: e.target.checked })}
        />
        <span className="text-muted-foreground">
          Fire on every new <span className="font-mono text-destructive">P1 - CRITICAL</span> brief
        </span>
      </label>
    </div>
  );
}

// ─── Watchlist ────────────────────────────────────────────────
function WatchlistPanel({
  watch, briefs, onOpen,
}: {
  watch: Record<string, { asset: OsintAsset; addedAt: string }>;
  briefs: Record<string, ThreatBrief>;
  onOpen: (id: string) => void;
}) {
  const items = Object.values(watch);
  return (
    <div className="mt-6 rounded-lg border border-border bg-card p-4">
      <h3 className="mb-2 text-xs font-mono uppercase tracking-widest text-muted-foreground">
        ★ Watchlist ({items.length})
      </h3>
      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          Star assets in the matrix to persist them here across sessions.
        </p>
      ) : (
        <ul className="space-y-1 text-xs">
          {items.map(({ asset }) => (
            <li key={asset.id} className="flex items-center justify-between gap-2">
              <button
                onClick={() => onOpen(asset.id)}
                className="truncate text-left font-mono text-primary underline-offset-2 hover:underline"
              >
                {asset.ip}:{asset.port}
              </button>
              <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                {briefs[asset.id]?.priority ?? "unscored"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ─── Audit / timeline ─────────────────────────────────────────
function AuditPanel({ events }: { events: AuditEvent[] }) {
  return (
    <div className="mt-6 rounded-lg border border-border bg-card p-4">
      <h3 className="mb-2 text-xs font-mono uppercase tracking-widest text-muted-foreground">
        Analysis Timeline
      </h3>
      {events.length === 0 ? (
        <p className="text-xs text-muted-foreground">No events yet.</p>
      ) : (
        <ul className="max-h-56 space-y-1.5 overflow-y-auto pr-1 text-xs">
          {events.slice(0, 40).map((e, i) => (
            <li key={i} className="flex gap-2">
              <span className="w-20 shrink-0 font-mono text-muted-foreground">
                {new Date(e.at).toLocaleTimeString()}
              </span>
              <span
                className={`w-16 shrink-0 font-mono uppercase ${
                  e.kind === "analyze"
                    ? "text-primary"
                    : e.kind === "delta"
                      ? "text-chart-4"
                      : "text-muted-foreground"
                }`}
              >
                {e.kind}
              </span>
              <span className="truncate">{e.detail}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ToolkitPanel({
  asset,
  toolkit,
  loading,
  error,
  onLoad,
}: {
  asset?: OsintAsset;
  toolkit?: ReconToolkit;
  loading: boolean;
  error?: string;
  onLoad: (asset: OsintAsset) => void;
}) {
  const [search, setSearch] = useState("");
  const [tags, setTags] = useState<{
    free: boolean;
    api: boolean;
    noAuth: boolean;
    favorites: boolean;
  }>({ free: false, api: false, noAuth: false, favorites: false });

  // Favorites: { [assetId]: string[] of tool URLs }, persisted to localStorage.
  const [favMap, setFavMap] = useState<Record<string, string[]>>({});
  useEffect(() => {
    try {
      const raw = localStorage.getItem("sentinel:favs");
      if (raw) setFavMap(JSON.parse(raw));
    } catch {
      /* ignore */
    }
  }, []);
  const favs = new Set(asset ? favMap[asset.id] ?? [] : []);
  const toggleFav = (url: string) => {
    if (!asset) return;
    setFavMap((prev) => {
      const cur = new Set(prev[asset.id] ?? []);
      if (cur.has(url)) cur.delete(url);
      else cur.add(url);
      const next = { ...prev, [asset.id]: Array.from(cur) };
      try {
        localStorage.setItem("sentinel:favs", JSON.stringify(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  };

  const filtered = useMemo(() => {
    if (!toolkit) return [];
    const q = search.trim().toLowerCase();
    const groups = toolkit.groups.map((g) => {
      const tools = g.tools.filter((t) => {
        if (tags.favorites && !favs.has(t.url)) return false;
        if (tags.free && t.pricing && t.pricing !== "free") return false;
        if (tags.api && !t.api) return false;
        if (tags.noAuth && t.registration) return false;
        if (!q) return true;
        return (
          t.name.toLowerCase().includes(q) ||
          t.description?.toLowerCase().includes(q) ||
          g.category.toLowerCase().includes(q)
        );
      });
      return { category: g.category, tools };
    });
    return groups.filter((g) => g.tools.length > 0);
  }, [toolkit, search, tags, favMap, asset]);

  const favTools = useMemo(() => {
    if (!toolkit) return [];
    const list: { name: string; url: string; category: string }[] = [];
    for (const g of toolkit.groups) {
      for (const t of g.tools) {
        if (favs.has(t.url))
          list.push({ name: t.name, url: t.url, category: g.category });
      }
    }
    return list.sort((a, b) => a.name.localeCompare(b.name));
  }, [toolkit, favMap, asset]);

  const matchCount = filtered.reduce((n, g) => n + g.tools.length, 0);

  if (!asset) {
    return (
      <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
        Select an asset to load matched investigation tools from the OSINT Framework.
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!toolkit) {
    return (
      <div className="rounded-lg border border-border bg-card p-4">
        <p className="mb-3 text-sm text-muted-foreground">
          Load curated OSINT Framework tools scoped to{" "}
          <span className="font-mono text-foreground">{asset.sector}</span> recon
          on <span className="font-mono text-foreground">{asset.ip}</span>.
        </p>
        <button
          onClick={() => onLoad(asset)}
          disabled={loading}
          className="rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
        >
          {loading ? "Loading toolkit…" : "Load Recon Toolkit"}
        </button>
      </div>
    );
  }
  const TagChip = ({
    active,
    onClick,
    label,
  }: {
    active: boolean;
    onClick: () => void;
    label: string;
  }) => (
    <button
      onClick={onClick}
      className={`rounded-full border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider transition-colors ${
        active
          ? "border-primary bg-primary/15 text-primary"
          : "border-border bg-background text-muted-foreground hover:bg-accent"
      }`}
    >
      {label}
    </button>
  );
  return (
    <div className="space-y-3 rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span className="font-mono">
          {filtered.length} categories · {matchCount} / {toolkit.total} tools ·{" "}
          <span className="text-chart-4">{favTools.length} starred</span>
        </span>
        <a
          href="https://github.com/lockfale/osint-framework"
          target="_blank"
          rel="noreferrer"
          className="underline-offset-2 hover:underline"
        >
          source
        </a>
      </div>
      {favTools.length > 0 && !tags.favorites && (
        <div className="rounded-md border border-chart-4/40 bg-chart-4/5 p-2">
          <div className="mb-1 text-[10px] font-mono uppercase tracking-wider text-chart-4">
            ★ Starred for this asset
          </div>
          <ul className="space-y-1 text-sm">
            {favTools.map((t) => (
              <li
                key={t.url}
                className="flex items-baseline justify-between gap-2"
              >
                <a
                  href={t.url}
                  target="_blank"
                  rel="noreferrer"
                  className="truncate text-primary underline-offset-2 hover:underline"
                >
                  {t.name}
                </a>
                <button
                  onClick={() => toggleFav(t.url)}
                  className="shrink-0 text-chart-4 hover:text-foreground"
                  aria-label="Unstar"
                >
                  <Star size={12} fill="currentColor" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="space-y-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search tools, categories, descriptions…"
          className="w-full rounded-md border border-border bg-background px-3 py-1.5 font-mono text-xs"
        />
        <div className="flex flex-wrap items-center gap-1.5">
          <TagChip
            active={tags.favorites}
            onClick={() => setTags((t) => ({ ...t, favorites: !t.favorites }))}
            label={`★ favorites (${favTools.length})`}
          />
          <TagChip
            active={tags.free}
            onClick={() => setTags((t) => ({ ...t, free: !t.free }))}
            label="free"
          />
          <TagChip
            active={tags.api}
            onClick={() => setTags((t) => ({ ...t, api: !t.api }))}
            label="api"
          />
          <TagChip
            active={tags.noAuth}
            onClick={() => setTags((t) => ({ ...t, noAuth: !t.noAuth }))}
            label="no signup"
          />
          {(search || tags.free || tags.api || tags.noAuth || tags.favorites) && (
            <button
              onClick={() => {
                setSearch("");
                setTags({ free: false, api: false, noAuth: false, favorites: false });
              }}
              className="ml-auto text-[10px] font-mono uppercase tracking-wider text-muted-foreground hover:text-foreground"
            >
              clear
            </button>
          )}
        </div>
      </div>
      <div className="max-h-[520px] space-y-3 overflow-y-auto pr-1">
        {filtered.length === 0 && (
          <div className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-muted-foreground">
            No tools match those filters.
          </div>
        )}
        {filtered.map((g) => (
          <details
            key={g.category}
            open={Boolean(search) || matchCount < 25}
            className="rounded-md border border-border/60"
          >
            <summary className="cursor-pointer select-none px-3 py-2 text-xs font-mono uppercase tracking-wider text-muted-foreground hover:bg-accent/30">
              {g.category}{" "}
              <span className="text-foreground">({g.tools.length})</span>
            </summary>
            <ul className="space-y-1 border-t border-border/60 p-2 text-sm">
              {g.tools.slice(0, 40).map((t) => (
                <li key={t.url} className="flex items-baseline gap-2">
                  <button
                    onClick={() => toggleFav(t.url)}
                    className={`shrink-0 transition-colors ${
                      favs.has(t.url)
                        ? "text-chart-4"
                        : "text-muted-foreground/50 hover:text-chart-4"
                    }`}
                    aria-label={favs.has(t.url) ? "Unstar" : "Star"}
                  >
                    <Star size={12} fill={favs.has(t.url) ? "currentColor" : "none"} />
                  </button>
                  <a
                    href={t.url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex-1 truncate text-primary underline-offset-2 hover:underline"
                    title={t.description}
                  >
                    {t.name}
                  </a>
                  <span className="shrink-0 font-mono text-[10px] uppercase text-muted-foreground">
                    {t.api ? "api " : ""}
                    {t.registration ? "auth " : ""}
                    {t.pricing && t.pricing !== "free" ? t.pricing : ""}
                  </span>
                </li>
              ))}
            </ul>
          </details>
        ))}
      </div>
    </div>
  );
}

function priorityStyle(p?: ThreatBrief["priority"]) {
  if (p === "P1 - CRITICAL") return "bg-destructive text-destructive-foreground";
  if (p === "P2 - HIGH") return "bg-chart-4 text-primary-foreground";
  if (p === "P3 - MONITOR") return "bg-chart-2 text-primary-foreground";
  return "bg-muted text-muted-foreground";
}

function AssetRow({
  asset,
  brief,
  selected,
  loading,
  bulk,
  watched,
  kevCount,
  columns,
  onAnalyze,
  onSelect,
  onToggleWatch,
}: {
  asset: OsintAsset;
  brief?: ThreatBrief;
  selected: boolean;
  loading: boolean;
  bulk?:
    | { status: "queued" }
    | { status: "running"; attempt: number }
    | { status: "retrying"; attempt: number; nextInMs: number; lastError: string }
    | { status: "done" }
    | { status: "error"; attempts: number; reason: string };
  watched: boolean;
  kevCount: number;
  columns: Record<ColumnKey, boolean>;
  onAnalyze: () => void;
  onSelect: () => void;
  onToggleWatch: () => void;
}) {
  return (
    <tr
      onClick={onSelect}
      className={`cursor-pointer border-t border-border transition-colors ${
        selected ? "bg-accent/60" : "hover:bg-accent/30"
      }`}
    >
      {columns.target && (
        <td className="px-3 py-3 font-mono text-xs">
          <div className="flex items-center gap-1.5">
            <button
              onClick={(e) => { e.stopPropagation(); onToggleWatch(); }}
              className={`shrink-0 ${watched ? "text-chart-4" : "text-muted-foreground/40 hover:text-chart-4"}`}
              aria-label={watched ? "Unwatch" : "Watch"}
            >
              <Star size={12} fill={watched ? "currentColor" : "none"} />
            </button>
            <span className="font-semibold text-foreground">{asset.ip}:{asset.port}</span>
          </div>
          <div className="mt-0.5 pl-4 text-muted-foreground">{asset.org}</div>
        </td>
      )}
      {columns.protocol && (
        <td className="px-3 py-3">
          <div>{asset.protocol}</div>
          <div className="font-mono text-[10px] text-muted-foreground">:{asset.port}</div>
        </td>
      )}
      {columns.location && (
        <td className="px-3 py-3 text-muted-foreground">{asset.location}</td>
      )}
      {columns.kev && (
        <td className="px-3 py-3">
          {kevCount > 0 ? (
            <span
              title={`${kevCount} CISA KEV entr${kevCount === 1 ? "y" : "ies"} match ${asset.protocol}`}
              className="inline-block rounded bg-destructive/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-destructive"
            >
              KEV ×{kevCount}
            </span>
          ) : (
            <span className="font-mono text-[10px] text-muted-foreground">—</span>
          )}
        </td>
      )}
      {columns.priority && (
        <td className="px-3 py-3">
          <span
            className={`inline-block rounded px-2 py-0.5 text-xs font-mono font-semibold ${priorityStyle(
              brief?.priority,
            )}`}
          >
            {brief?.priority ??
              (bulk?.status === "queued"
                ? "QUEUED"
                : bulk?.status === "running"
                  ? bulk.attempt > 1
                    ? `RUNNING… (try ${bulk.attempt})`
                    : "RUNNING…"
                  : bulk?.status === "retrying"
                    ? `RETRY in ${Math.round(bulk.nextInMs / 100) / 10}s`
                    : bulk?.status === "error"
                      ? "ERROR"
                      : "UNSCORED")}
          </span>
          {bulk?.status === "error" && (
            <div
              className="mt-1 max-w-[220px] truncate font-mono text-[10px] text-destructive"
              title={`Failed after ${bulk.attempts} attempts: ${bulk.reason}`}
            >
              {bulk.reason}
            </div>
          )}
          {bulk?.status === "retrying" && (
            <div
              className="mt-1 max-w-[220px] truncate font-mono text-[10px] text-muted-foreground"
              title={bulk.lastError}
            >
              attempt {bulk.attempt} failed — retrying
            </div>
          )}
        </td>
      )}
      {columns.analyzed && (
        <td className="px-3 py-3 font-mono text-[10px] text-muted-foreground">
          {brief ? new Date(brief.generatedAt).toLocaleTimeString() : "—"}
        </td>
      )}
      <td className="px-3 py-3 text-right">
        <div className="flex items-center justify-end gap-1">
          <Link
            to="/asset/$ip/$port"
            params={{ ip: asset.ip, port: String(asset.port) }}
            search={{ protocol: asset.protocol, sector: asset.sector, location: asset.location, org: asset.org }}
            onClick={(e) => e.stopPropagation()}
            className="rounded-md border border-border bg-background p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
            title="Open shareable brief"
          >
            <ExternalLink size={12} />
          </Link>
          <button
          onClick={(e) => {
            e.stopPropagation();
            onAnalyze();
          }}
          disabled={loading}
          className="rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
        >
          {loading ? "Analyzing…" : brief ? "Re-run" : "Analyze"}
        </button>
        </div>
      </td>
    </tr>
  );
}

function BriefPanel({
  brief, error, asset, kev,
}: {
  brief?: ThreatBrief;
  error?: string;
  asset?: OsintAsset;
  kev?: import("@/lib/sentinel.functions").KevMatch[];
}) {
  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!brief) {
    return (
      <div className="space-y-3">
        <div className="rounded-lg border border-dashed border-border p-6 text-sm text-muted-foreground">
          Select an asset and run <span className="font-mono">Analyze</span> to fuse
          technical OSINT with Tavily strategic intelligence.
        </div>
        {asset && kev && kev.length > 0 && <KevList kev={kev} protocol={asset.protocol} />}
      </div>
    );
  }
  return (
    <div className="space-y-4 rounded-lg border border-border bg-card p-5">
      <div className="flex items-center justify-between">
        <span
          className={`rounded px-2 py-0.5 text-xs font-mono font-semibold ${priorityStyle(
            brief.priority,
          )}`}
        >
          {brief.priority}
        </span>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>{new Date(brief.generatedAt).toLocaleTimeString()}</span>
          <Link
            to="/asset/$ip/$port"
            params={{ ip: brief.asset.ip, port: String(brief.asset.port) }}
            search={{
              protocol: brief.asset.protocol,
              sector: brief.asset.sector,
              location: brief.asset.location,
              org: brief.asset.org,
            }}
            className="inline-flex items-center gap-1 text-primary hover:underline"
          >
            <ExternalLink size={10} /> share
          </Link>
        </div>
      </div>
      <div>
        <div className="text-xs uppercase tracking-widest text-muted-foreground">
          Target
        </div>
        <div className="mt-1 font-mono text-sm">
          {brief.asset.ip}:{brief.asset.port} · {brief.asset.protocol}
        </div>
        <div className="text-sm text-muted-foreground">
          {brief.asset.org} — {brief.asset.location}
        </div>
      </div>
      {kev && kev.length > 0 && <KevList kev={kev} protocol={brief.asset.protocol} />}
      <div>
        <div className="text-xs uppercase tracking-widest text-muted-foreground">
          AI Threat Summary
        </div>
        <p className="mt-1 whitespace-pre-wrap text-sm leading-relaxed">
          {brief.summary}
        </p>
      </div>
      {brief.sources.length > 0 && (
        <div>
          <div className="text-xs uppercase tracking-widest text-muted-foreground">
            Sources
          </div>
          <ul className="mt-2 space-y-1 text-sm">
            {brief.sources.map((s) => (
              <li key={s.url}>
                <a
                  href={s.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-primary underline-offset-2 hover:underline"
                >
                  {s.title || s.url}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function KevList({
  kev, protocol,
}: { kev: import("@/lib/sentinel.functions").KevMatch[]; protocol: string }) {
  const [open, setOpen] = useState(false);
  const shown = open ? kev : kev.slice(0, 3);
  return (
    <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-xs font-mono uppercase tracking-widest text-destructive">
          CISA KEV · {protocol} ({kev.length})
        </div>
        {kev.length > 3 && (
          <button
            onClick={() => setOpen((v) => !v)}
            className="text-[10px] font-mono uppercase text-muted-foreground hover:text-foreground"
          >
            {open ? "collapse" : "show all"}
          </button>
        )}
      </div>
      <ul className="space-y-1 text-xs">
        {shown.map((k) => (
          <li key={k.cveId} className="flex items-baseline gap-2">
            <a
              href={`https://nvd.nist.gov/vuln/detail/${k.cveId}`}
              target="_blank"
              rel="noreferrer"
              className="w-32 shrink-0 font-mono text-primary underline-offset-2 hover:underline"
            >
              {k.cveId}
            </a>
            <span className="truncate text-muted-foreground" title={k.shortDescription}>
              {k.vendor} — {k.product}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
