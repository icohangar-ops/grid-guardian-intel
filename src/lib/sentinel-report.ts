import type { ThreatBrief, OsintAsset, KevMatch, AttackMapping } from "./sentinel.functions";
import { scoreAttack, extractSnippets } from "./sentinel.functions";
import type { AuditEvent } from "./sentinel-storage";

export type SocReportInput = {
  asset: OsintAsset;
  brief?: ThreatBrief;
  kev?: KevMatch[];
  delta?: { added: string[]; closed: string[] } | null;
  deltaQuery?: string;
  audit: AuditEvent[];
  watched?: boolean;
  analyst?: string;
};

function fmt(dt: string | undefined) {
  if (!dt) return "—";
  try { return new Date(dt).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z"); }
  catch { return dt; }
}

function tacticGroups(attack: AttackMapping[]) {
  const g = new Map<string, { name: string; items: AttackMapping[] }>();
  for (const a of attack) {
    const cur = g.get(a.tacticId) ?? { name: a.tacticName, items: [] };
    cur.items.push(a);
    g.set(a.tacticId, cur);
  }
  return Array.from(g.entries());
}

export function buildSocMarkdown(input: SocReportInput): string {
  const { asset, brief, kev = [], delta, deltaQuery, audit, watched, analyst } = input;
  const now = new Date().toISOString();
  const pr = brief?.priority ?? "UNSCORED";
  const assetTimeline = audit.filter((e) => e.assetId === asset.id).slice(0, 25);
  const deltaEvents = audit.filter((e) => e.kind === "delta").slice(0, 5);

  const lines: string[] = [];
  lines.push(`# SOC Threat Report — ${asset.ip}:${asset.port}`);
  lines.push("");
  lines.push(`> **Priority:** \`${pr}\`  ·  **Sector:** ${asset.sector}  ·  **Protocol:** ${asset.protocol}  ·  **Watched:** ${watched ? "yes ★" : "no"}`);
  lines.push(`> **Generated:** ${now}${analyst ? `  ·  **Analyst:** ${analyst}` : ""}`);
  lines.push("");
  lines.push("## 1. Target");
  lines.push("");
  lines.push("| Field | Value |");
  lines.push("|---|---|");
  lines.push(`| Asset ID | \`${asset.id}\` |`);
  lines.push(`| IP / Port | \`${asset.ip}\` : \`${asset.port}\` |`);
  lines.push(`| Protocol | ${asset.protocol} |`);
  lines.push(`| Sector | ${asset.sector} |`);
  lines.push(`| Organization | ${asset.org} |`);
  lines.push(`| Location | ${asset.location}${asset.province ? ` (${asset.province})` : ""} |`);
  lines.push("");

  lines.push("## 2. Threat Brief");
  lines.push("");
  if (brief) {
    lines.push(`**Priority:** ${brief.priority}  ·  **Generated:** ${fmt(brief.generatedAt)}`);
    lines.push("");
    lines.push(brief.summary.trim());
    lines.push("");
    if (brief.sources.length) {
      lines.push("### Sources");
      lines.push("");
      brief.sources.forEach((s, i) => {
        lines.push(`${i + 1}. [${s.title || s.url}](${s.url})`);
      });
      lines.push("");
    }
  } else {
    lines.push("_No Tavily brief has been generated for this asset yet._");
    lines.push("");
  }

  lines.push("## 3. CISA KEV / NVD Enrichment");
  lines.push("");
  if (kev.length === 0) {
    lines.push(`_No CISA Known-Exploited-Vulnerabilities match protocol **${asset.protocol}**._`);
    lines.push("");
  } else {
    lines.push(`Matched **${kev.length}** KEV entr${kev.length === 1 ? "y" : "ies"} for protocol **${asset.protocol}**.`);
    lines.push("");
    lines.push("| CVE | Vendor | Product | Description |");
    lines.push("|---|---|---|---|");
    for (const k of kev.slice(0, 25)) {
      const desc = (k.shortDescription || "").replace(/\|/g, "\\|").replace(/\s+/g, " ").slice(0, 160);
      lines.push(`| [${k.cveId}](https://nvd.nist.gov/vuln/detail/${k.cveId}) | ${k.vendor} | ${k.product} | ${desc} |`);
    }
    if (kev.length > 25) lines.push(`| … | | | _${kev.length - 25} more_ |`);
    lines.push("");
  }

  lines.push("## 4. MITRE ATT&CK Mapping");
  lines.push("");
  const attack = brief?.attack ?? [];
  if (attack.length === 0) {
    lines.push("_No techniques inferred from this brief._");
    lines.push("");
  } else {
    for (const [tacticId, { name, items }] of tacticGroups(attack)) {
      lines.push(`**${name}** \`${tacticId}\``);
      lines.push("");
      for (const t of items) {
        const matrix = t.matrix === "ics" ? "ICS" : "Enterprise";
        lines.push(`- [${t.techniqueId}](${t.url}) — ${t.techniqueName} · _${matrix}_ · matched: \`${t.matched.join(", ")}\``);
      }
      lines.push("");
    }
  }

  lines.push("## 5. Watchlist Delta");
  lines.push("");
  if (delta && (delta.added.length || delta.closed.length)) {
    lines.push(`Query \`${deltaQuery || "(default)"}\` — \`+${delta.added.length}\` new / \`-${delta.closed.length}\` closed since last snapshot.`);
    lines.push("");
    if (delta.added.length) {
      lines.push("**New services**");
      delta.added.slice(0, 25).forEach((id) => lines.push(`- \`${id}\`${id === asset.id ? " ← **this asset**" : ""}`));
      if (delta.added.length > 25) lines.push(`- _+${delta.added.length - 25} more_`);
      lines.push("");
    }
    if (delta.closed.length) {
      lines.push("**Closed services**");
      delta.closed.slice(0, 25).forEach((id) => lines.push(`- \`${id}\``));
      if (delta.closed.length > 25) lines.push(`- _+${delta.closed.length - 25} more_`);
      lines.push("");
    }
  } else {
    lines.push("_No delta recorded for the current query snapshot._");
    lines.push("");
  }
  if (deltaEvents.length) {
    lines.push("Recent global delta events:");
    for (const e of deltaEvents) lines.push(`- \`${fmt(e.at)}\` — ${e.detail}`);
    lines.push("");
  }

  lines.push("## 6. Timeline / Audit Log");
  lines.push("");
  if (assetTimeline.length === 0) {
    lines.push("_No audit events recorded for this asset._");
    lines.push("");
  } else {
    lines.push("| Time (UTC) | Event | Detail |");
    lines.push("|---|---|---|");
    for (const e of assetTimeline) {
      lines.push(`| \`${fmt(e.at)}\` | ${e.kind} | ${e.detail.replace(/\|/g, "\\|")} |`);
    }
    lines.push("");
  }

  lines.push("## 7. Recommended Actions");
  lines.push("");
  const acts: string[] = [];
  if (pr === "P1 - CRITICAL") acts.push("Escalate to on-call ICS analyst within 15 minutes; page sector ISAC.");
  if (pr === "P2 - HIGH") acts.push("Open incident ticket, notify asset owner within 1 hour.");
  if (kev.length) acts.push(`Cross-check asset firmware against ${kev.length} KEV entr${kev.length === 1 ? "y" : "ies"} above.`);
  if (attack.some((a) => a.matrix === "ics")) acts.push("Validate segmentation between IT and OT for the affected protocol.");
  if (delta?.added.includes(asset.id)) acts.push("Confirm this service was intentionally exposed — it is new since last snapshot.");
  if (!brief) acts.push("Run Tavily analysis to fuse geopolitical and threat-actor context.");
  if (!acts.length) acts.push("Continue monitoring; re-poll on standard cadence.");
  acts.forEach((a) => lines.push(`- [ ] ${a}`));
  lines.push("");

  lines.push("---");
  lines.push(`_Sentinel-OSINT · Report ID \`${asset.id}@${now}\`_`);
  return lines.join("\n");
}

// Very small, dependency-free markdown → HTML for the print window.
// Covers what buildSocMarkdown emits: h1-h3, tables, lists, task lists,
// blockquotes, links, code spans, bold, hr.
export function markdownToHtml(md: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const inline = (s: string) =>
    esc(s)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|[\s(])_([^_]+)_/g, "$1<em>$2</em>")
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

  const lines = md.split("\n");
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^---\s*$/.test(line)) { out.push("<hr/>"); i++; continue; }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) { out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`); i++; continue; }
    if (/^>\s?/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^>\s?/, "")); i++; }
      out.push(`<blockquote>${inline(buf.join(" "))}</blockquote>`);
      continue;
    }
    if (/^\|/.test(line) && i + 1 < lines.length && /^\|[\s:|-]+\|$/.test(lines[i + 1])) {
      const cells = (row: string) => row.split("|").slice(1, -1).map((c) => c.trim());
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && /^\|/.test(lines[i])) { rows.push(cells(lines[i])); i++; }
      out.push(
        `<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead>` +
          `<tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`,
      );
      continue;
    }
    const li = /^(\s*)-\s+(\[[ x]\]\s+)?(.*)$/.exec(line);
    if (li) {
      const items: string[] = [];
      while (i < lines.length) {
        const m = /^(\s*)-\s+(\[([ x])\]\s+)?(.*)$/.exec(lines[i]);
        if (!m) break;
        if (m[2]) {
          const checked = m[3] === "x" ? "checked" : "";
          items.push(`<li class="task"><input type="checkbox" ${checked} disabled/> ${inline(m[4])}</li>`);
        } else {
          items.push(`<li>${inline(m[4])}</li>`);
        }
        i++;
      }
      out.push(`<ul>${items.join("")}</ul>`);
      continue;
    }
    const ol = /^(\s*)(\d+)\.\s+(.*)$/.exec(line);
    if (ol) {
      const items: string[] = [];
      while (i < lines.length) {
        const m = /^(\s*)(\d+)\.\s+(.*)$/.exec(lines[i]);
        if (!m) break;
        items.push(`<li>${inline(m[3])}</li>`);
        i++;
      }
      out.push(`<ol>${items.join("")}</ol>`);
      continue;
    }
    if (line.trim() === "") { i++; continue; }
    // Paragraph: collect until blank/structural.
    const buf: string[] = [line];
    i++;
    while (i < lines.length && lines[i].trim() !== "" &&
      !/^(#{1,3}\s|>|\||-\s|\d+\.\s|---\s*$)/.test(lines[i])) {
      buf.push(lines[i]); i++;
    }
    out.push(`<p>${inline(buf.join(" "))}</p>`);
  }
  return out.join("\n");
}

export function printableHtml(title: string, bodyHtml: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"/><title>${title.replace(/</g, "&lt;")}</title>
<style>
  :root { color-scheme: light; }
  body { font: 13px/1.55 -apple-system, "Segoe UI", Inter, Roboto, sans-serif; color:#111; max-width: 860px; margin: 32px auto; padding: 0 24px; }
  h1 { font-size: 22px; margin: 0 0 4px; border-bottom: 2px solid #111; padding-bottom: 6px; }
  h2 { font-size: 15px; margin: 22px 0 8px; text-transform: uppercase; letter-spacing: .08em; color:#222; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
  h3 { font-size: 13px; margin: 14px 0 6px; }
  blockquote { margin: 6px 0 12px; padding: 8px 12px; background:#f4f6f8; border-left: 3px solid #b91c1c; font-size: 12px; }
  table { width:100%; border-collapse: collapse; margin: 6px 0 14px; font-size: 12px; }
  th, td { border: 1px solid #d5d8dc; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background:#f4f6f8; text-transform: uppercase; font-size: 10px; letter-spacing: .06em; }
  code { background:#f0f2f5; padding: 1px 4px; border-radius: 3px; font: 11px/1.4 ui-monospace, Menlo, monospace; }
  a { color:#0b57d0; text-decoration: none; }
  ul, ol { margin: 4px 0 12px 20px; }
  li.task { list-style: none; margin-left: -18px; }
  hr { border:none; border-top: 1px solid #ccc; margin: 24px 0 8px; }
  p { margin: 6px 0; }
  @media print { body { margin: 0; padding: 12mm; max-width: none; } a { color: #000; } }
</style></head><body>${bodyHtml}
<script>window.addEventListener("load",()=>setTimeout(()=>window.print(),150));</script>
</body></html>`;
}

export function openPrintWindow(title: string, md: string) {
  const w = window.open("", "_blank", "width=900,height=1000");
  if (!w) return;
  w.document.open();
  w.document.write(printableHtml(title, markdownToHtml(md)));
  w.document.close();
}

export function downloadMarkdown(filename: string, md: string) {
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

// ─── ATT&CK technique evidence export ─────────────────────────

export type EvidenceExport = {
  filenameBase: string;
  json: string;
  markdown: string;
  signalsCsv: string;
  title: string;
};

function safeSlug(s: string): string {
  return s.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "evidence";
}

function csvCell(v: unknown): string {
  const s = v == null ? "" : String(v);
  return `"${s.replace(/"/g, '""')}"`;
}

export function downloadCsv(filename: string, csv: string) {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

export function buildTechniqueEvidence(
  technique: AttackMapping,
  brief: ThreatBrief | undefined,
): EvidenceExport {
  const conf = scoreAttack(technique);
  const snippets = brief?.summary
    ? extractSnippets(brief.summary, technique.matched, { radius: 160, maxPerKeyword: 3 })
    : [];
  const actors = technique.matched
    .filter((k) => k.startsWith("actor:"))
    .map((k) => k.slice(6));
  const keywords = technique.matched.filter(
    (k) => !k.startsWith("actor:") && k.toLowerCase() !== technique.techniqueId.toLowerCase(),
  );
  const idHit = technique.matched.some(
    (k) => k.toLowerCase() === technique.techniqueId.toLowerCase(),
  );
  const generatedAt = new Date().toISOString();

  const jsonObj = {
    schema: "sentinel.attack-evidence/v1",
    exportedAt: generatedAt,
    technique: {
      id: technique.techniqueId,
      name: technique.techniqueName,
      matrix: technique.matrix,
      url: technique.url,
      tactic: { id: technique.tacticId, name: technique.tacticName },
    },
    confidence: {
      score: conf.score,
      band: conf.band,
      factors: conf.factors,
    },
    matchedSignals: {
      idReference: idHit ? technique.techniqueId : null,
      keywords,
      actors,
      raw: technique.matched,
    },
    brief: brief
      ? {
          assetId: brief.asset.id,
          asset: brief.asset,
          priority: brief.priority,
          generatedAt: brief.generatedAt,
          summary: brief.summary,
          sources: brief.sources,
        }
      : null,
    snippets: snippets.map((s) => ({
      keyword: s.keyword.replace(/^actor:/, "actor:"),
      snippet: s.snippet,
    })),
  };

  const title = `ATT&CK Evidence — ${technique.techniqueId} · ${technique.techniqueName}`;
  const lines: string[] = [];
  lines.push(`# ${title}`, "");
  lines.push(`- **Tactic:** ${technique.tacticName} (${technique.tacticId})`);
  lines.push(`- **Matrix:** ${technique.matrix === "ics" ? "ICS" : "Enterprise"}`);
  lines.push(`- **Confidence:** ${conf.score}% (${conf.band.toUpperCase()})`);
  lines.push(`- **Exported:** ${generatedAt}`);
  if (brief) {
    lines.push(
      `- **Source brief:** ${brief.asset.id} — ${brief.asset.org} · ${brief.asset.location} · priority ${brief.priority} · generated ${brief.generatedAt}`,
    );
  }
  lines.push(`- **MITRE reference:** ${technique.url}`, "");

  lines.push(`## Rationale`, "");
  for (const f of conf.factors) lines.push(`- ${f}`);
  lines.push("");

  lines.push(`## Matched signals (${technique.matched.length})`, "");
  if (idHit) lines.push(`- **ID reference:** ${technique.techniqueId}`);
  if (keywords.length) {
    lines.push(`- **Keywords:**`);
    for (const k of keywords) lines.push(`  - "${k}"`);
  }
  if (actors.length) {
    lines.push(`- **Threat actors:**`);
    for (const a of actors) lines.push(`  - ${a}`);
  }
  if (!idHit && !keywords.length && !actors.length) lines.push(`- (none captured)`);
  lines.push("");

  lines.push(`## Source snippets`, "");
  if (snippets.length === 0) {
    lines.push(`_No direct quote extracted — match likely inferred from technique ID or actor._`);
  } else {
    for (const s of snippets) {
      lines.push(`> **${s.keyword.replace(/^actor:/, "actor:")}** — ${s.snippet.replace(/\n+/g, " ")}`);
      lines.push("");
    }
  }
  lines.push("");

  lines.push(`## Sources`, "");
  if (!brief || brief.sources.length === 0) {
    lines.push(`_No sources attached to brief._`);
  } else {
    for (const src of brief.sources) {
      lines.push(`- [${src.title || src.url}](${src.url})`);
    }
  }
  lines.push("");

  if (brief?.summary) {
    lines.push(`## Full brief summary`, "", brief.summary, "");
  }

  const stamp = generatedAt.replace(/[:.]/g, "-");
  const assetSlug = brief ? safeSlug(brief.asset.id) : "no-asset";
  const filenameBase = `attack-evidence_${technique.techniqueId}_${assetSlug}_${stamp}`;

  // ─── Matched signals CSV (one row per ID / keyword / actor) ──
  const briefTs = brief?.generatedAt ?? "";
  const snippetsByKeyword = new Map<string, string[]>();
  for (const s of snippets) {
    const key = s.keyword.toLowerCase();
    const arr = snippetsByKeyword.get(key) ?? [];
    arr.push(s.snippet.replace(/\s+/g, " ").trim());
    snippetsByKeyword.set(key, arr);
  }
  const csvRows: string[][] = [
    [
      "signal_type",
      "value",
      "technique_id",
      "technique_name",
      "tactic_id",
      "tactic_name",
      "matrix",
      "confidence_score",
      "confidence_band",
      "asset_id",
      "asset_org",
      "asset_location",
      "brief_generated_at",
      "exported_at",
      "snippet",
    ],
  ];
  const pushSignal = (type: string, value: string, lookup: string) => {
    const snips = snippetsByKeyword.get(lookup.toLowerCase()) ?? [];
    const snippet = snips.join(" | ");
    csvRows.push([
      type,
      value,
      technique.techniqueId,
      technique.techniqueName,
      technique.tacticId,
      technique.tacticName,
      technique.matrix,
      String(conf.score),
      conf.band,
      brief?.asset.id ?? "",
      brief?.asset.org ?? "",
      brief?.asset.location ?? "",
      briefTs,
      generatedAt,
      snippet,
    ]);
  };
  if (idHit) pushSignal("id_reference", technique.techniqueId, technique.techniqueId);
  for (const k of keywords) pushSignal("keyword", k, k);
  for (const a of actors) pushSignal("actor", a, `actor:${a}`);
  const signalsCsv = csvRows.map((r) => r.map(csvCell).join(",")).join("\n");

  return {
    filenameBase,
    json: JSON.stringify(jsonObj, null, 2),
    markdown: lines.join("\n"),
    signalsCsv,
    title,
  };
}

export function downloadJson(filename: string, json: string) {
  const blob = new Blob([json], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}