import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useMutation } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import {
  analyzeAsset,
  scoreAttack,
  extractSnippets,
  type OsintAsset,
  type ThreatBrief,
  type AttackMapping,
} from "@/lib/sentinel.functions";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { ExternalLink, Download } from "lucide-react";
import { loadBriefs, saveBrief } from "@/lib/sentinel-storage";
import {
  buildTechniqueEvidence,
  downloadJson,
  downloadMarkdown,
  openPrintWindow,
  downloadCsv,
} from "@/lib/sentinel-report";

type Search = {
  protocol?: string;
  sector?: string;
  location?: string;
  org?: string;
};

export const Route = createFileRoute("/asset/$ip/$port")({
  validateSearch: (s: Record<string, unknown>): Search => ({
    protocol: typeof s.protocol === "string" ? s.protocol : undefined,
    sector: typeof s.sector === "string" ? s.sector : undefined,
    location: typeof s.location === "string" ? s.location : undefined,
    org: typeof s.org === "string" ? s.org : undefined,
  }),
  head: ({ params }) => ({
    meta: [
      {
        title: `Sentinel Brief — ${params.ip}:${params.port}`,
      },
      {
        name: "description",
        content: `Shareable threat brief for exposed asset ${params.ip}:${params.port}.`,
      },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: SharedBrief,
});

function SharedBrief() {
  const { ip, port } = Route.useParams();
  const search = Route.useSearch();
  const asset: OsintAsset = useMemo(
    () => ({
      id: `${ip}:${port}`,
      ip,
      port: Number(port) || 0,
      protocol: search.protocol || "Unknown",
      sector: search.sector || "Infrastructure",
      location: search.location || "Unknown",
      org: search.org || "Unknown operator",
    }),
    [ip, port, search.protocol, search.sector, search.location, search.org],
  );

  const analyzeFn = useServerFn(analyzeAsset);
  const [brief, setBrief] = useState<ThreatBrief | undefined>(undefined);
  const [activeTech, setActiveTech] = useState<AttackMapping | null>(null);
  const mut = useMutation({
    mutationFn: () => analyzeFn({ data: { asset } }),
    onSuccess: (b) => {
      setBrief(b);
      saveBrief(b);
    },
  });

  useEffect(() => {
    const cached = loadBriefs()[asset.id];
    if (cached) setBrief(cached);
  }, [asset.id]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-6">
          <Link
            to="/"
            className="text-xs font-mono uppercase tracking-widest text-muted-foreground hover:text-foreground"
          >
            ← Sentinel-OSINT
          </Link>
          <span className="text-xs font-mono text-muted-foreground">
            Shareable Brief
          </span>
        </div>
      </header>
      <main className="mx-auto max-w-4xl px-6 py-8">
        <h1 className="font-mono text-2xl font-bold">
          {asset.ip}:{asset.port}
        </h1>
        <div className="mt-1 text-sm text-muted-foreground">
          {asset.protocol} · {asset.sector} · {asset.org} — {asset.location}
        </div>
        <div className="mt-6">
          <button
            onClick={() => mut.mutate()}
            disabled={mut.isPending}
            className="rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
          >
            {mut.isPending
              ? "Analyzing…"
              : brief
                ? "Re-run analysis"
                : "Run analysis"}
          </button>
        </div>
        {mut.error && (
          <div className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            {mut.error.message}
          </div>
        )}
        {brief && (
          <article className="mt-6 space-y-4 rounded-lg border border-border bg-card p-6">
            <div className="flex items-center justify-between">
              <span className="rounded bg-destructive px-2 py-0.5 font-mono text-xs font-semibold text-destructive-foreground">
                {brief.priority}
              </span>
              <span className="text-xs text-muted-foreground">
                {new Date(brief.generatedAt).toLocaleString()}
              </span>
            </div>
            <p className="whitespace-pre-wrap text-sm leading-relaxed">
              {brief.summary}
            </p>
            {brief.attack && brief.attack.length > 0 && (
              <div className="rounded-md border border-border bg-background/40 p-3">
                <div className="mb-2 text-xs font-mono uppercase tracking-widest text-muted-foreground">
                  MITRE ATT&amp;CK · {brief.attack.length}
                </div>
                <div className="flex flex-wrap gap-1">
                  {brief.attack.map((t) => {
                    const conf = scoreAttack(t);
                    const bandStyle =
                      conf.band === "high"
                        ? "border-destructive/60 bg-destructive/15 text-destructive"
                        : conf.band === "medium"
                          ? "border-chart-3/50 bg-chart-3/10 text-chart-3"
                          : "border-muted-foreground/40 bg-muted/40 text-muted-foreground";
                    return (
                      <button
                        type="button"
                        key={`${t.matrix}:${t.techniqueId}`}
                        onClick={() => setActiveTech(t)}
                        title={`${t.tacticName} · ${t.techniqueName} — click for evidence`}
                        className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] hover:bg-accent ${
                          t.matrix === "ics"
                            ? "border-chart-4/40 bg-chart-4/10 text-chart-4"
                            : "border-primary/40 bg-primary/10 text-primary"
                        }`}
                      >
                        <span className="font-semibold">{t.techniqueId}</span>
                        <span className="text-foreground/80">{t.techniqueName}</span>
                        <span
                          className={`ml-1 rounded-sm border px-1 py-[1px] text-[9px] font-semibold tabular-nums ${bandStyle}`}
                        >
                          {conf.score}%
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
            {brief.sources.length > 0 && (
              <ul className="space-y-1 text-sm">
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
            )}
          </article>
        )}
      </main>
      <SharedEvidenceDialog technique={activeTech} brief={brief} onClose={() => setActiveTech(null)} />
    </div>
  );
}

function SharedEvidenceDialog({
  ...args
}: Parameters<typeof SharedEvidenceDialogInner>[0]) {
  return <SharedEvidenceDialogInner {...args} />;
}

function SharedFacetRow({
  label,
  options,
  selected,
  onToggle,
  hint,
}: {
  label: string;
  options: { id: string; label: string }[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  hint?: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {label}
      </span>
      {options.map((o) => {
        const active = selected.has(o.id);
        return (
          <button
            key={o.id}
            type="button"
            onClick={() => onToggle(o.id)}
            className={`rounded-sm border px-1.5 py-[1px] font-mono text-[10px] uppercase tracking-widest transition-colors ${
              active
                ? "border-primary/60 bg-primary/15 text-primary"
                : "border-border bg-background text-muted-foreground hover:bg-accent"
            }`}
            aria-pressed={active}
          >
            {o.label}
          </button>
        );
      })}
      {hint && (
        <span className="ml-1 font-mono text-[10px] text-muted-foreground/80">{hint}</span>
      )}
    </div>
  );
}

function SharedEvidenceDialogInner({
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
  const [filter, setFilter] = useState("");
  const q = filter.trim().toLowerCase();
  const matchStr = (s: string) => !q || s.toLowerCase().includes(q);
  type SrcType = "id" | "keyword" | "actor";
  type Band = "high" | "medium" | "low";
  const [typeSet, setTypeSet] = useState<Set<SrcType>>(
    () => new Set<SrcType>(["id", "keyword", "actor"]),
  );
  const [bandSet, setBandSet] = useState<Set<Band>>(
    () => new Set<Band>(["high", "medium", "low"]),
  );
  const [rangeMs, setRangeMs] = useState<number | null>(null);
  type SortMode = "type" | "confidence" | "recent";
  const [sortMode, setSortMode] = useState<SortMode>("type");
  const kindOf = (k: string): SrcType =>
    k.startsWith("actor:") ? "actor"
    : k.toLowerCase() === technique.techniqueId.toLowerCase() ? "id"
    : "keyword";
  const bandGated = !bandSet.has(conf.band as Band);
  const briefAgeMs = brief?.generatedAt
    ? Date.now() - new Date(brief.generatedAt).getTime()
    : null;
  const rangeGated =
    rangeMs !== null && (briefAgeMs === null || briefAgeMs > rangeMs);
  const facetGated = bandGated || rangeGated;
  const visibleMatched = facetGated
    ? []
    : technique.matched.filter(
        (k) => typeSet.has(kindOf(k)) && matchStr(k.startsWith("actor:") ? k.slice(6) : k),
      );
  const visibleSnippets = facetGated
    ? []
    : snippets.filter(
        (s) =>
          typeSet.has(kindOf(s.keyword)) &&
          (matchStr(s.snippet) || matchStr(s.keyword.replace(/^actor:/, ""))),
      );
  const summaryLc = (brief?.summary ?? "").toLowerCase();
  const sigWeight = (k: string) => {
    const kind = kindOf(k);
    return kind === "id" ? 3 : kind === "actor" ? 2 : 1;
  };
  const sigCount = (k: string) => {
    const needle = (k.startsWith("actor:") ? k.slice(6) : k).toLowerCase();
    if (!needle) return 0;
    let c = 0, i = 0;
    while ((i = summaryLc.indexOf(needle, i)) !== -1) { c++; i += needle.length; }
    return c;
  };
  const sigLast = (k: string) => {
    const needle = (k.startsWith("actor:") ? k.slice(6) : k).toLowerCase();
    return needle ? summaryLc.lastIndexOf(needle) : -1;
  };
  const signalCmp = (a: string, b: string) => {
    if (sortMode === "confidence") return sigWeight(b) - sigWeight(a) || sigCount(b) - sigCount(a);
    if (sortMode === "recent") return sigLast(b) - sigLast(a) || sigWeight(b) - sigWeight(a);
    return 0;
  };
  const snippetPos = (s: { snippet: string }) =>
    summaryLc.indexOf(s.snippet.slice(0, 40).toLowerCase().replace(/^…\s*/, ""));
  const snippetCmp = (a: { keyword: string; snippet: string }, b: { keyword: string; snippet: string }) => {
    if (sortMode === "confidence") return sigWeight(b.keyword) - sigWeight(a.keyword);
    if (sortMode === "recent") return snippetPos(b) - snippetPos(a);
    return 0;
  };
  const orderedMatched = sortMode === "type" ? visibleMatched : [...visibleMatched].sort(signalCmp);
  const orderedSnippets = sortMode === "type" ? visibleSnippets : [...visibleSnippets].sort(snippetCmp);
  const anyFacetActive = typeSet.size < 3 || bandSet.size < 3 || rangeMs !== null;
  const toggle = <T,>(set: Set<T>, val: T, setter: (s: Set<T>) => void) => {
    const next = new Set(set);
    if (next.has(val)) next.delete(val); else next.add(val);
    setter(next);
  };
  const relAge = (iso: string) => {
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  };
  const bandStyle =
    conf.band === "high"
      ? "border-destructive/60 bg-destructive/15 text-destructive"
      : conf.band === "medium"
        ? "border-chart-3/50 bg-chart-3/10 text-chart-3"
        : "border-muted-foreground/40 bg-muted/40 text-muted-foreground";
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
            <span className={`shrink-0 rounded-sm border px-1.5 py-[1px] text-[10px] font-semibold tabular-nums ${bandStyle}`}>
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
              <select
                value={sortMode}
                onChange={(e) => setSortMode(e.target.value as SortMode)}
                className="h-7 rounded border border-border bg-background px-1.5 font-mono text-[10px] uppercase tracking-widest outline-none focus:border-primary"
                title="Sort matched signals & snippets"
              >
                <option value="type">Sort: Source type</option>
                <option value="confidence">Sort: Highest confidence</option>
                <option value="recent">Sort: Newest in brief</option>
              </select>
            </div>
            <div className="mt-2 space-y-1.5">
              <SharedFacetRow
                label="Source type"
                options={[
                  { id: "id", label: "ID ref" },
                  { id: "keyword", label: "Keyword" },
                  { id: "actor", label: "Actor" },
                ]}
                selected={typeSet as Set<string>}
                onToggle={(v) => toggle(typeSet, v as SrcType, setTypeSet)}
              />
              <SharedFacetRow
                label="Confidence"
                options={[
                  { id: "high", label: "High" },
                  { id: "medium", label: "Med" },
                  { id: "low", label: "Low" },
                ]}
                selected={bandSet as Set<string>}
                onToggle={(v) => toggle(bandSet, v as Band, setBandSet)}
                hint={`Technique band: ${conf.band.toUpperCase()}`}
              />
              <SharedFacetRow
                label="Age"
                options={[
                  { id: "3600000", label: "1h" },
                  { id: "86400000", label: "24h" },
                  { id: "604800000", label: "7d" },
                  { id: "2592000000", label: "30d" },
                  { id: "all", label: "All" },
                ]}
                selected={new Set<string>([rangeMs === null ? "all" : String(rangeMs)])}
                onToggle={(v) => setRangeMs(v === "all" ? null : Number(v))}
                hint={brief?.generatedAt ? `Brief age: ${relAge(brief.generatedAt)}` : undefined}
              />
              {anyFacetActive && (
                <button
                  type="button"
                  onClick={() => {
                    setTypeSet(new Set(["id", "keyword", "actor"]));
                    setBandSet(new Set(["high", "medium", "low"]));
                    setRangeMs(null);
                  }}
                  className="rounded border border-border bg-background px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
                >
                  Reset facets
                </button>
              )}
              {facetGated && (
                <div className="rounded border border-dashed border-border/70 bg-muted/30 px-2 py-1 font-mono text-[10px] text-muted-foreground">
                  {bandGated && `Hidden by confidence facet (technique band ${conf.band.toUpperCase()}). `}
                  {rangeGated && `Hidden by age facet (brief older than selected window).`}
                </div>
              )}
            </div>
          </div>
          <section>
            <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Rationale</div>
            <ul className="list-disc space-y-1 pl-5 text-xs leading-relaxed">
              {conf.factors.map((f, i) => <li key={i}>{f}</li>)}
            </ul>
          </section>
          <section>
            <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Matched signals ({visibleMatched.length}
              {q ? ` / ${technique.matched.length}` : ""})
            </div>
            {q && visibleMatched.length === 0 ? (
              <div className="rounded border border-dashed border-border p-2 text-xs text-muted-foreground">
                No signals match “{filter}”.
              </div>
            ) : (
            <div className="flex flex-wrap gap-1">
              {orderedMatched.map((k) => (
                <span key={k} className="rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px]">
                  {k.startsWith("actor:") ? `actor: ${k.slice(6)}` : `“${k}”`}
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
                No direct quotes located in the brief text.
              </div>
            ) : visibleSnippets.length === 0 ? (
              <div className="rounded border border-dashed border-border p-2 text-xs text-muted-foreground">
                No snippets match “{filter}”.
              </div>
            ) : (
              <ul className="space-y-2">
                {orderedSnippets.map((s, i) => (
                  <li key={i} className="rounded border border-border bg-background/60 p-2 text-xs leading-relaxed">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      matched: “{s.keyword.replace(/^actor:/, "actor:")}”
                    </div>
                    {s.snippet}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
        <DialogFooter>
          <div className="mr-auto flex flex-wrap items-center gap-1">
            <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Export evidence:
            </span>
            <button
              type="button"
              onClick={() => {
                const ev = buildTechniqueEvidence(technique, brief);
                downloadJson(`${ev.filenameBase}.json`, ev.json);
              }}
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
            >
              <Download size={10} /> JSON
            </button>
            <button
              type="button"
              onClick={() => {
                const ev = buildTechniqueEvidence(technique, brief);
                downloadCsv(`${ev.filenameBase}_signals.csv`, ev.signalsCsv);
              }}
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
              title="Download matched signals with timestamps as CSV"
            >
              <Download size={10} /> CSV
            </button>
            <button
              type="button"
              onClick={() => {
                const ev = buildTechniqueEvidence(technique, brief);
                downloadCsv(`${ev.filenameBase}_snippets.csv`, ev.snippetsCsv);
              }}
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
              title="Download source snippets with technique/tactic linkage and timestamps"
            >
              <Download size={10} /> Snippets CSV
            </button>
            <button
              type="button"
              onClick={() => {
                const ev = buildTechniqueEvidence(technique, brief);
                downloadMarkdown(`${ev.filenameBase}.md`, ev.markdown);
              }}
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 font-mono text-[10px] uppercase tracking-widest hover:bg-accent"
            >
              <Download size={10} /> MD
            </button>
            <button
              type="button"
              onClick={() => {
                const ev = buildTechniqueEvidence(technique, brief);
                openPrintWindow(ev.title, ev.markdown);
              }}
              className="inline-flex items-center gap-1 rounded border border-primary/60 bg-primary/10 px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20"
            >
              <Download size={10} /> PDF
            </button>
          </div>
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