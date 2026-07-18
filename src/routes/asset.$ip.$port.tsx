import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useMutation } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import {
  analyzeAsset,
  scoreAttack,
  type OsintAsset,
  type ThreatBrief,
} from "@/lib/sentinel.functions";
import { loadBriefs, saveBrief } from "@/lib/sentinel-storage";

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
                      <a
                        key={`${t.matrix}:${t.techniqueId}`}
                        href={t.url}
                        target="_blank"
                        rel="noreferrer"
                        title={`${t.tacticName} · ${t.techniqueName}\nConfidence ${conf.score}% (${conf.band})\nRationale: ${conf.rationale}`}
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
                      </a>
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
    </div>
  );
}