import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { queryOptions, useSuspenseQuery, useMutation, useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Star, ArrowUpDown, ExternalLink, Bell, Download, Radar } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  listExposedAssets,
  analyzeAsset,
  getReconToolkit,
  getKevForProtocols,
  sendWebhook,
  scoreAttack,
  extractSnippets,
  type ThreatBrief,
  type OsintAsset,
  type ReconToolkit,
  type KevReport,
  type AttackMapping,
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
import {
  buildSocMarkdown,
  downloadMarkdown,
  openPrintWindow,
  buildTechniqueEvidence,
  downloadJson,
} from "@/lib/sentinel-report";

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
          <AttackHeatmap briefs={briefs} />
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
            audit={audit}
            delta={delta}
            deltaQuery={activeQuery}
            watched={selected ? Boolean(watch[selected]) : false}
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

// ─── ATT&CK tactics heatmap (time-ranged) ─────────────────────
const RANGE_PRESETS: { key: string; label: string; ms: number | null }[] = [
  { key: "1h", label: "1h", ms: 60 * 60 * 1000 },
  { key: "24h", label: "24h", ms: 24 * 60 * 60 * 1000 },
  { key: "7d", label: "7d", ms: 7 * 24 * 60 * 60 * 1000 },
  { key: "30d", label: "30d", ms: 30 * 24 * 60 * 60 * 1000 },
  { key: "all", label: "all", ms: null },
];

function AttackHeatmap({ briefs }: { briefs: Record<string, ThreatBrief> }) {
  const [rangeKey, setRangeKey] = useState<string>("24h");
  const [matrixFilter, setMatrixFilter] = useState<"all" | "ics" | "enterprise">("all");
  const [drill, setDrill] = useState<{ tacticId: string; focusTechnique?: string } | null>(null);

  const stats = useMemo(() => {
    const range = RANGE_PRESETS.find((r) => r.key === rangeKey) ?? RANGE_PRESETS[1];
    const cutoff = range.ms == null ? 0 : Date.now() - range.ms;
    const inRange: ThreatBrief[] = [];
    for (const b of Object.values(briefs)) {
      const t = Date.parse(b.generatedAt);
      if (!Number.isFinite(t)) continue;
      if (range.ms != null && t < cutoff) continue;
      inRange.push(b);
    }
    type TacticStat = {
      tacticId: string;
      tacticName: string;
      count: number; // technique occurrences
      briefs: Set<string>; // asset ids
      techniques: Map<string, { name: string; matrix: "ics" | "enterprise"; count: number; url: string }>;
      contributions: Contribution[];
    };
    const tactics = new Map<string, TacticStat>();
    let totalTechHits = 0;
    for (const b of inRange) {
      for (const a of b.attack ?? []) {
        if (matrixFilter !== "all" && a.matrix !== matrixFilter) continue;
        totalTechHits++;
        const cur = tactics.get(a.tacticId) ?? {
          tacticId: a.tacticId,
          tacticName: a.tacticName,
          count: 0,
          briefs: new Set<string>(),
          techniques: new Map(),
          contributions: [] as Contribution[],
        };
        cur.count++;
        cur.briefs.add(b.asset.id);
        const tk = cur.techniques.get(a.techniqueId) ?? {
          name: a.techniqueName,
          matrix: a.matrix,
          count: 0,
          url: a.url,
        };
        tk.count++;
        cur.techniques.set(a.techniqueId, tk);
        cur.contributions.push({ brief: b, mapping: a });
        tactics.set(a.tacticId, cur);
      }
    }
    const sorted = Array.from(tactics.values()).sort((a, b) => b.count - a.count);
    const max = sorted[0]?.count ?? 0;
    return { rows: sorted, max, totalBriefs: inRange.length, totalTechHits };
  }, [briefs, rangeKey, matrixFilter]);

  const activeTactic = drill ? stats.rows.find((r) => r.tacticId === drill.tacticId) : undefined;

  return (
    <div className="mt-6 rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h3 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
          MITRE ATT&amp;CK Heatmap — Tactic Frequency
        </h3>
        <span className="font-mono text-[10px] text-muted-foreground">
          {stats.totalBriefs} brief{stats.totalBriefs === 1 ? "" : "s"} · {stats.totalTechHits} technique hits
        </span>
        <div className="ml-auto flex items-center gap-1">
          {(["all", "ics", "enterprise"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMatrixFilter(m)}
              className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                matrixFilter === m
                  ? "border-primary bg-primary/15 text-primary"
                  : "border-border bg-background text-muted-foreground hover:bg-accent"
              }`}
            >
              {m}
            </button>
          ))}
          <span className="mx-1 text-border">|</span>
          {RANGE_PRESETS.map((r) => (
            <button
              key={r.key}
              onClick={() => setRangeKey(r.key)}
              className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                rangeKey === r.key
                  ? "border-primary bg-primary/15 text-primary"
                  : "border-border bg-background text-muted-foreground hover:bg-accent"
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>
      {stats.rows.length === 0 ? (
        <div className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
          No ATT&amp;CK techniques matched in this range. Analyze more assets or widen the window.
        </div>
      ) : (
        <ul className="space-y-2">
          {stats.rows.map((t) => {
            const pct = stats.max ? (t.count / stats.max) * 100 : 0;
            const top = Array.from(t.techniques.values())
              .sort((a, b) => b.count - a.count)
              .slice(0, 6);
            const intensity = 0.15 + 0.65 * (t.count / stats.max);
            return (
              <li key={t.tacticId} className="rounded-md border border-border/60 bg-background/40 p-2">
                <button
                  type="button"
                  onClick={() => setDrill({ tacticId: t.tacticId })}
                  title="View contributing briefs, techniques and timestamps"
                  className="flex w-full items-baseline gap-2 rounded text-left text-xs hover:bg-accent/40"
                >
                  <span className="w-40 shrink-0 font-semibold text-foreground">
                    {t.tacticName}
                  </span>
                  <span className="w-16 shrink-0 font-mono text-[10px] text-muted-foreground">
                    {t.tacticId}
                  </span>
                  <div className="relative h-4 flex-1 overflow-hidden rounded bg-muted">
                    <div
                      className="h-full bg-destructive"
                      style={{ width: `${pct}%`, opacity: intensity }}
                    />
                  </div>
                  <span className="w-14 shrink-0 text-right font-mono tabular-nums text-foreground">
                    {t.count}×
                  </span>
                  <span
                    className="w-16 shrink-0 text-right font-mono text-[10px] text-muted-foreground"
                    title={`Distinct assets contributing to this tactic`}
                  >
                    {t.briefs.size} asset{t.briefs.size === 1 ? "" : "s"}
                  </span>
                </button>
                <div className="mt-1.5 flex flex-wrap gap-1 pl-40">
                  {top.map((tk) => {
                    const [id, ] = Array.from(t.techniques.entries()).find(([, v]) => v === tk) ?? [];
                    return (
                      <button
                        key={id}
                        type="button"
                        onClick={() => setDrill({ tacticId: t.tacticId, focusTechnique: id })}
                        className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] hover:bg-accent ${
                          tk.matrix === "ics"
                            ? "border-chart-4/40 bg-chart-4/10 text-chart-4"
                            : "border-primary/40 bg-primary/10 text-primary"
                        }`}
                        title={`Drill down: ${tk.name} — ${tk.count} hit${tk.count === 1 ? "" : "s"}`}
                      >
                        <span className="font-semibold">{id}</span>
                        <span className="text-foreground/80">×{tk.count}</span>
                      </button>
                    );
                  })}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      <TacticDrilldownDialog
        tactic={activeTactic ?? null}
        focusTechnique={drill?.focusTechnique}
        onClose={() => setDrill(null)}
      />
    </div>
  );
}

type Contribution = { brief: ThreatBrief; mapping: AttackMapping };

function TacticDrilldownDialog({
  tactic,
  focusTechnique,
  onClose,
}: {
  tactic:
    | {
        tacticId: string;
        tacticName: string;
        count: number;
        briefs: Set<string>;
        techniques: Map<string, { name: string; matrix: "ics" | "enterprise"; count: number; url: string }>;
        contributions: Contribution[];
      }
    | null;
  focusTechnique?: string;
  onClose: () => void;
}) {
  const open = tactic !== null;
  if (!tactic) {
    return (
      <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
        <DialogContent />
      </Dialog>
    );
  }
  // Group contributions by technique, sorted by frequency then newest.
  const grouped = new Map<string, Contribution[]>();
  for (const c of tactic.contributions) {
    const arr = grouped.get(c.mapping.techniqueId) ?? [];
    arr.push(c);
    grouped.set(c.mapping.techniqueId, arr);
  }
  const groupOrder = Array.from(grouped.entries()).sort((a, b) => {
    if (focusTechnique) {
      if (a[0] === focusTechnique) return -1;
      if (b[0] === focusTechnique) return 1;
    }
    return b[1].length - a[1].length;
  });
  for (const [, arr] of groupOrder) {
    arr.sort(
      (a, b) => Date.parse(b.brief.generatedAt) - Date.parse(a.brief.generatedAt),
    );
  }
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="font-mono">
            {tactic.tacticName} · {tactic.tacticId}
          </DialogTitle>
          <DialogDescription>
            {tactic.count} technique hit{tactic.count === 1 ? "" : "s"} across{" "}
            {tactic.briefs.size} asset{tactic.briefs.size === 1 ? "" : "s"} ·{" "}
            {grouped.size} distinct technique{grouped.size === 1 ? "" : "s"}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {groupOrder.map(([techniqueId, contribs]) => {
            const first = contribs[0].mapping;
            return (
              <section
                key={techniqueId}
                className={`rounded-md border p-3 ${
                  focusTechnique === techniqueId
                    ? "border-primary/60 bg-primary/5"
                    : "border-border bg-background/40"
                }`}
              >
                <div className="mb-2 flex flex-wrap items-baseline gap-2">
                  <span
                    className={`rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold ${
                      first.matrix === "ics"
                        ? "border-chart-4/40 bg-chart-4/10 text-chart-4"
                        : "border-primary/40 bg-primary/10 text-primary"
                    }`}
                  >
                    {techniqueId}
                  </span>
                  <span className="text-sm font-semibold text-foreground">{first.techniqueName}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {contribs.length} hit{contribs.length === 1 ? "" : "s"}
                  </span>
                  <a
                    href={first.url}
                    target="_blank"
                    rel="noreferrer"
                    className="ml-auto inline-flex items-center gap-1 font-mono text-[10px] text-muted-foreground hover:text-foreground"
                  >
                    attack.mitre.org <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <ul className="space-y-2">
                  {contribs.map((c, i) => {
                    const conf = scoreAttack(c.mapping);
                    const snippets = extractSnippets(c.brief.summary, c.mapping.matched, {
                      radius: 100,
                      maxPerKeyword: 1,
                    });
                    return (
                      <li
                        key={`${c.brief.asset.id}:${i}`}
                        className="rounded border border-border/70 bg-background/70 p-2 text-xs"
                      >
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Link
                            to="/asset/$ip/$port"
                            params={{
                              ip: c.brief.asset.ip,
                              port: String(c.brief.asset.port),
                            }}
                            className="font-mono text-foreground hover:underline"
                          >
                            {c.brief.asset.id}
                          </Link>
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {c.brief.asset.org} · {c.brief.asset.location}
                          </span>
                          <span
                            className={`rounded-sm border px-1 py-[1px] font-mono text-[10px] ${bandStyleFor(conf.band)}`}
                            title={conf.factors.join(" · ")}
                          >
                            {conf.score}%
                          </span>
                          <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                            <time dateTime={c.brief.generatedAt} title={c.brief.generatedAt}>
                              {formatRelative(c.brief.generatedAt)}
                            </time>
                          </span>
                        </div>
                        {c.mapping.matched.length > 0 && (
                          <div className="mb-1 flex flex-wrap gap-1">
                            {c.mapping.matched.slice(0, 8).map((k) => (
                              <span
                                key={k}
                                className="rounded border border-border bg-muted/40 px-1 py-[1px] font-mono text-[10px] text-foreground"
                              >
                                {k.startsWith("actor:") ? `actor:${k.slice(6)}` : `“${k}”`}
                              </span>
                            ))}
                          </div>
                        )}
                        {snippets.length > 0 ? (
                          <ul className="space-y-1">
                            {snippets.slice(0, 3).map((s, j) => (
                              <li
                                key={j}
                                className="rounded border border-border/60 bg-background/60 p-1.5 text-[11px] leading-relaxed"
                              >
                                <HighlightedSnippet
                                  text={s.snippet}
                                  keyword={s.keyword.replace(/^actor:/, "")}
                                />
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <div className="text-[11px] italic text-muted-foreground">
                            No direct quote — inferred from technique ID or actor mapping.
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </section>
            );
          })}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function formatRelative(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const diff = Date.now() - t;
  const abs = Math.abs(diff);
  const m = Math.round(abs / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(t).toISOString().slice(0, 10);
}

function bandStyleFor(band: "high" | "medium" | "low"): string {
  return band === "high"
    ? "border-destructive/60 bg-destructive/15 text-destructive"
    : band === "medium"
      ? "border-chart-3/50 bg-chart-3/10 text-chart-3"
      : "border-muted-foreground/40 bg-muted/40 text-muted-foreground";
}

function AttackChip({ t, onOpen }: { t: AttackMapping; onOpen: (t: AttackMapping) => void }) {
  const conf = scoreAttack(t);
  return (
    <button
      type="button"
      onClick={() => onOpen(t)}
      title={`${t.techniqueName} · Confidence ${conf.score}% (${conf.band}) — click for evidence`}
      className={`group inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] hover:bg-accent focus:outline-none focus:ring-1 focus:ring-primary ${
        t.matrix === "ics"
          ? "border-chart-4/40 bg-chart-4/10 text-chart-4"
          : "border-primary/40 bg-primary/10 text-primary"
      }`}
    >
      <span className="font-semibold">{t.techniqueId}</span>
      <span className="text-foreground/80">{t.techniqueName}</span>
      <span
        className={`ml-1 rounded-sm border px-1 py-[1px] text-[9px] font-semibold tabular-nums ${bandStyleFor(conf.band)}`}
        aria-label={`Confidence ${conf.score} percent, ${conf.band}`}
      >
        {conf.score}%
      </span>
    </button>
  );
}

function AttackEvidenceDialog({
  technique,
  brief,
  onClose,
}: {
  technique: AttackMapping | null;
  brief: ThreatBrief | undefined;
  onClose: () => void;
}) {
  const open = technique !== null;
  if (!technique) {
    return (
      <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
        <DialogContent />
      </Dialog>
    );
  }
  const conf = scoreAttack(technique);
  const snippets = brief?.summary
    ? extractSnippets(brief.summary, technique.matched, { radius: 120, maxPerKeyword: 2 })
    : [];
  const actorMatches = technique.matched.filter((k) => k.startsWith("actor:"));
  const idHit = technique.matched.some(
    (k) => k.toLowerCase() === technique.techniqueId.toLowerCase(),
  );
  const [filter, setFilter] = useState("");
  const q = filter.trim().toLowerCase();
  const matchStr = (s: string) => !q || s.toLowerCase().includes(q);
  const idHitVisible = idHit && (matchStr(technique.techniqueId) || matchStr("id reference"));
  const keywordMatches = technique.matched.filter(
    (k) => k.toLowerCase() !== technique.techniqueId.toLowerCase() && !k.startsWith("actor:"),
  );
  const visibleKeywords = keywordMatches.filter(matchStr);
  const visibleActors = actorMatches.filter((k) => matchStr(k.replace(/^actor:/, "")));
  const visibleSnippets = snippets.filter(
    (s) => matchStr(s.snippet) || matchStr(s.keyword.replace(/^actor:/, "")),
  );
  const visibleSourceCount =
    (idHitVisible ? 1 : 0) + visibleKeywords.length + visibleActors.length;
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <div className="flex items-start justify-between gap-3">
            <div>
              <DialogTitle className="font-mono">
                {technique.techniqueId} · {technique.techniqueName}
              </DialogTitle>
              <DialogDescription>
                Tactic: {technique.tacticName} ({technique.tacticId}) ·{" "}
                {technique.matrix === "ics" ? "ICS Matrix" : "Enterprise Matrix"}
              </DialogDescription>
            </div>
            <span
              className={`shrink-0 rounded-sm border px-1.5 py-[1px] text-[10px] font-semibold tabular-nums ${bandStyleFor(conf.band)}`}
            >
              {conf.score}% · {conf.band.toUpperCase()}
            </span>
          </div>
        </DialogHeader>

        <div className="space-y-4 text-sm">
          <div>
            <label className="mb-1 block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Filter evidence
            </label>
            <div className="flex items-center gap-2">
              <input
                type="search"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter keywords, actors, or snippet text…"
                className="h-7 flex-1 rounded border border-border bg-background px-2 font-mono text-xs outline-none focus:border-primary"
              />
              {filter && (
                <button
                  type="button"
                  onClick={() => setFilter("")}
                  className="rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
                >
                  Clear
                </button>
              )}
            </div>
            {q && (
              <div className="mt-1 font-mono text-[10px] text-muted-foreground">
                {visibleSourceCount} signal{visibleSourceCount === 1 ? "" : "s"} · {visibleSnippets.length} snippet
                {visibleSnippets.length === 1 ? "" : "s"}
              </div>
            )}
          </div>

          <section>
            <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Rationale
            </div>
            <ul className="list-disc space-y-1 pl-5 text-xs leading-relaxed">
              {conf.factors.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          </section>

          <section>
            <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Matched signals ({visibleSourceCount}
              {q ? ` / ${technique.matched.length}` : ""})
            </div>
            {q && visibleSourceCount === 0 ? (
              <div className="rounded border border-dashed border-border p-2 text-xs text-muted-foreground">
                No signals match “{filter}”.
              </div>
            ) : (
            <div className="flex flex-wrap gap-1">
              {idHitVisible && (
                <span className="rounded border border-destructive/60 bg-destructive/15 px-1.5 py-0.5 font-mono text-[10px] text-destructive">
                  ID reference: {technique.techniqueId}
                </span>
              )}
              {visibleKeywords.map((k) => (
                  <span
                    key={k}
                    className="rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-foreground"
                  >
                    “{k}”
                  </span>
                ))}
              {visibleActors.map((k) => (
                <span
                  key={k}
                  className="rounded border border-chart-3/50 bg-chart-3/10 px-1.5 py-0.5 font-mono text-[10px] text-chart-3"
                >
                  actor: {k.replace(/^actor:/, "")}
                </span>
              ))}
            </div>
            )}
          </section>

          <section>
            <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Source snippets from brief ({visibleSnippets.length}
              {q ? ` / ${snippets.length}` : ""})
            </div>
            {snippets.length === 0 ? (
              <div className="rounded border border-dashed border-border p-2 text-xs text-muted-foreground">
                No direct quotes located in the brief text. Match likely comes from an inferred
                actor or from the technique ID appearing outside quoted context.
              </div>
            ) : visibleSnippets.length === 0 ? (
              <div className="rounded border border-dashed border-border p-2 text-xs text-muted-foreground">
                No snippets match “{filter}”.
              </div>
            ) : (
              <ul className="space-y-2">
                {visibleSnippets.map((s, i) => (
                  <li key={i} className="rounded border border-border bg-background/60 p-2 text-xs leading-relaxed">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      matched: “{s.keyword.replace(/^actor:/, "actor:")}”
                    </div>
                    <HighlightedSnippet text={s.snippet} keyword={q || s.keyword.replace(/^actor:/, "")} />
                  </li>
                ))}
              </ul>
            )}
          </section>

          {brief && brief.sources.length > 0 && (
            <section>
              <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Brief sources ({brief.sources.length})
              </div>
              <ul className="space-y-1 text-xs">
                {brief.sources.map((src) => (
                  <li key={src.url}>
                    <a
                      href={src.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-primary hover:underline"
                    >
                      <ExternalLink size={10} />
                      {src.title || src.url}
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <DialogFooter>
          <EvidenceExportButtons technique={technique} brief={brief} />
          <a
            href={technique.url}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
          >
            View on attack.mitre.org <ExternalLink size={10} />
          </a>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function EvidenceExportButtons({
  technique,
  brief,
}: {
  technique: AttackMapping;
  brief: ThreatBrief | undefined;
}) {
  const doExport = (kind: "json" | "pdf" | "md") => {
    const ev = buildTechniqueEvidence(technique, brief);
    if (kind === "json") downloadJson(`${ev.filenameBase}.json`, ev.json);
    else if (kind === "md") downloadMarkdown(`${ev.filenameBase}.md`, ev.markdown);
    else openPrintWindow(ev.title, ev.markdown);
  };
  return (
    <div className="mr-auto flex flex-wrap items-center gap-1">
      <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        Export evidence:
      </span>
      <button
        type="button"
        onClick={() => doExport("json")}
        className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
        title="Download rationale, matched signals and sources as JSON"
      >
        <Download size={10} /> JSON
      </button>
      <button
        type="button"
        onClick={() => doExport("md")}
        className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
        title="Download as Markdown"
      >
        <Download size={10} /> MD
      </button>
      <button
        type="button"
        onClick={() => doExport("pdf")}
        className="inline-flex items-center gap-1 rounded border border-primary/60 bg-primary/10 px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20"
        title="Open print-ready view (save as PDF from the browser dialog)"
      >
        <Download size={10} /> PDF
      </button>
    </div>
  );
}

function HighlightedSnippet({ text, keyword }: { text: string; keyword: string }) {
  if (!keyword) return <span>{text}</span>;
  const lower = text.toLowerCase();
  const k = keyword.toLowerCase();
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  let idx = lower.indexOf(k);
  let i = 0;
  while (idx !== -1) {
    if (idx > cursor) parts.push(text.slice(cursor, idx));
    parts.push(
      <mark key={i++} className="rounded bg-chart-4/30 px-0.5 text-foreground">
        {text.slice(idx, idx + k.length)}
      </mark>,
    );
    cursor = idx + k.length;
    idx = lower.indexOf(k, cursor);
  }
  if (cursor < text.length) parts.push(text.slice(cursor));
  return <span>{parts}</span>;
}

function AttackPanel({
  attack,
  brief,
}: {
  attack: AttackMapping[];
  brief?: ThreatBrief;
}) {
  const [active, setActive] = useState<AttackMapping | null>(null);
  if (!attack.length) {
    return (
      <div>
        <div className="text-xs uppercase tracking-widest text-muted-foreground">
          MITRE ATT&amp;CK
        </div>
        <div className="mt-1 text-xs text-muted-foreground">
          No techniques matched from this brief.
        </div>
      </div>
    );
  }
  // Group by tactic.
  const groups = new Map<
    string,
    { tacticId: string; tacticName: string; items: typeof attack }
  >();
  for (const a of attack) {
    const g = groups.get(a.tacticId) ?? {
      tacticId: a.tacticId,
      tacticName: a.tacticName,
      items: [] as typeof attack,
    };
    g.items.push(a);
    groups.set(a.tacticId, g);
  }
  return (
    <div>
      <div className="flex items-center justify-between">
        <div className="text-xs uppercase tracking-widest text-muted-foreground">
          MITRE ATT&amp;CK · {attack.length}
        </div>
        <a
          href="https://attack.mitre.org/matrices/ics/"
          target="_blank"
          rel="noreferrer"
          className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:text-primary"
        >
          ICS Matrix ↗
        </a>
      </div>
      <div className="mt-2 space-y-2">
        {Array.from(groups.values()).map((g) => (
          <div key={g.tacticId} className="rounded-md border border-border bg-background/40 p-2">
            <div className="mb-1 flex items-baseline justify-between">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-foreground">
                {g.tacticName}
              </div>
              <div className="font-mono text-[10px] text-muted-foreground">{g.tacticId}</div>
            </div>
            <div className="flex flex-wrap gap-1">
              {g.items.map((t) => (
                <AttackChip key={`${t.matrix}:${t.techniqueId}`} t={t} onOpen={setActive} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <AttackEvidenceDialog technique={active} brief={brief} onClose={() => setActive(null)} />
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
  brief, error, asset, kev, audit, delta, deltaQuery, watched,
}: {
  brief?: ThreatBrief;
  error?: string;
  asset?: OsintAsset;
  kev?: import("@/lib/sentinel.functions").KevMatch[];
  audit: AuditEvent[];
  delta: { added: string[]; closed: string[] } | null;
  deltaQuery: string;
  watched: boolean;
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
      <AttackPanel attack={brief.attack ?? []} brief={brief} />
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
      <SocReportPanel
        asset={brief.asset}
        brief={brief}
        kev={kev}
        audit={audit}
        delta={delta}
        deltaQuery={deltaQuery}
        watched={watched}
      />
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

function SocReportPanel({
  asset, brief, kev, audit, delta, deltaQuery, watched,
}: {
  asset: OsintAsset;
  brief?: ThreatBrief;
  kev?: import("@/lib/sentinel.functions").KevMatch[];
  audit: AuditEvent[];
  delta: { added: string[]; closed: string[] } | null;
  deltaQuery: string;
  watched: boolean;
}) {
  const [preview, setPreview] = useState(false);
  const [copied, setCopied] = useState(false);
  const md = useMemo(
    () => buildSocMarkdown({
      asset, brief, kev: kev ?? [], delta, deltaQuery, audit, watched,
    }),
    [asset, brief, kev, delta, deltaQuery, audit, watched],
  );
  const filename = `sentinel-report-${asset.ip.replace(/[.:]/g, "_")}-${asset.port}.md`;
  const title = `SOC Threat Report — ${asset.ip}:${asset.port}`;
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked */ }
  };
  return (
    <div className="rounded-md border border-border/70 bg-background/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
          SOC Report
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-1.5 text-xs">
          <button
            onClick={onCopy}
            className="rounded-md border border-border bg-background px-2 py-1 hover:bg-accent"
            title="Copy markdown to clipboard"
          >
            {copied ? "Copied ✓" : "Copy MD"}
          </button>
          <button
            onClick={() => downloadMarkdown(filename, md)}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 hover:bg-accent"
          >
            <Download size={11} /> .md
          </button>
          <button
            onClick={() => openPrintWindow(title, md)}
            className="rounded-md border border-primary/40 bg-primary/10 px-2 py-1 font-medium text-primary hover:bg-primary/20"
            title="Open print dialog — choose 'Save as PDF'"
          >
            Print / PDF
          </button>
          <button
            onClick={() => setPreview((v) => !v)}
            className="rounded-md border border-border bg-background px-2 py-1 hover:bg-accent"
          >
            {preview ? "Hide" : "Preview"}
          </button>
        </div>
      </div>
      {preview && (
        <pre className="mt-2 max-h-80 overflow-auto rounded border border-border bg-background/70 p-2 font-mono text-[10px] leading-snug text-muted-foreground whitespace-pre-wrap">
          {md}
        </pre>
      )}
    </div>
  );
}
