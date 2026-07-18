import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { queryOptions, useSuspenseQuery, useMutation } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Star } from "lucide-react";
import {
  listExposedAssets,
  analyzeAsset,
  getReconToolkit,
  type ThreatBrief,
  type OsintAsset,
  type ReconToolkit,
} from "@/lib/sentinel.functions";

const assetsQuery = (query?: string, cursor?: string) =>
  queryOptions({
    queryKey: ["sentinel", "assets", query ?? "", cursor ?? ""],
    queryFn: () => listExposedAssets({ data: { query, cursor } }),
  });

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
  // Briefs are keyed by asset.id (ip:port), so mapping survives across pages.
  const [briefs, setBriefs] = useState<Record<string, ThreatBrief>>({});
  const [toolkits, setToolkits] = useState<Record<string, ReconToolkit>>({});
  const [selected, setSelected] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (asset: OsintAsset) => analyzeFn({ data: { asset } }),
    onSuccess: (brief) => {
      setBriefs((prev) => ({ ...prev, [brief.asset.id]: brief }));
      setSelected(brief.asset.id);
    },
  });

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

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border">
        <div className="mx-auto max-w-7xl px-6 py-8">
          <div className="flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-destructive animate-pulse" />
            <span className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Sentinel-OSINT // Operational
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
              Exposed Assets ({feed.assets.length}) ·{" "}
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
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Target</th>
                  <th className="px-3 py-2 text-left font-medium">Protocol</th>
                  <th className="px-3 py-2 text-left font-medium">Location</th>
                  <th className="px-3 py-2 text-left font-medium">Priority</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {feed.assets.map((asset) => (
                  <AssetRow
                    key={asset.id}
                    asset={asset}
                    brief={briefs[asset.id]}
                    selected={selected === asset.id}
                    loading={mutation.isPending && mutation.variables?.id === asset.id}
                    onAnalyze={() => mutation.mutate(asset)}
                    onSelect={() => setSelected(asset.id)}
                  />
                ))}
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
        </section>

        <aside>
          <h2 className="mb-3 text-xs font-mono uppercase tracking-widest text-muted-foreground">
            Threat Brief
          </h2>
          <BriefPanel
            brief={selected ? briefs[selected] : undefined}
            error={mutation.error?.message}
          />
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
  onAnalyze,
  onSelect,
}: {
  asset: OsintAsset;
  brief?: ThreatBrief;
  selected: boolean;
  loading: boolean;
  onAnalyze: () => void;
  onSelect: () => void;
}) {
  return (
    <tr
      onClick={onSelect}
      className={`cursor-pointer border-t border-border transition-colors ${
        selected ? "bg-accent/60" : "hover:bg-accent/30"
      }`}
    >
      <td className="px-3 py-3 font-mono text-xs">
        <div className="font-semibold text-foreground">{asset.ip}:{asset.port}</div>
        <div className="text-muted-foreground">{asset.org}</div>
      </td>
      <td className="px-3 py-3">{asset.protocol}</td>
      <td className="px-3 py-3 text-muted-foreground">{asset.location}</td>
      <td className="px-3 py-3">
        <span
          className={`inline-block rounded px-2 py-0.5 text-xs font-mono font-semibold ${priorityStyle(
            brief?.priority,
          )}`}
        >
          {brief?.priority ?? "UNSCORED"}
        </span>
      </td>
      <td className="px-3 py-3 text-right">
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
      </td>
    </tr>
  );
}

function BriefPanel({ brief, error }: { brief?: ThreatBrief; error?: string }) {
  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!brief) {
    return (
      <div className="rounded-lg border border-dashed border-border p-6 text-sm text-muted-foreground">
        Select an asset and run <span className="font-mono">Analyze</span> to fuse
        technical OSINT with Tavily strategic intelligence.
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
        <span className="text-xs text-muted-foreground">
          {new Date(brief.generatedAt).toLocaleTimeString()}
        </span>
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
