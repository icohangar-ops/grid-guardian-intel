import { createServerFn } from "@tanstack/react-start";

export type OsintAsset = {
  id: string;
  ip: string;
  port: number;
  protocol: string;
  location: string;
  org: string;
  sector: string;
};

const MOCK_ASSETS: OsintAsset[] = [
  { id: "a1", ip: "203.0.113.42", port: 502, protocol: "Modbus", location: "Eastern Europe", org: "National Power Grid Authority", sector: "Energy" },
  { id: "a2", ip: "198.51.100.17", port: 102, protocol: "Siemens S7", location: "Germany", org: "Rhein Water Works", sector: "Water Treatment" },
  { id: "a3", ip: "192.0.2.88", port: 44818, protocol: "EtherNet/IP", location: "Texas, USA", org: "Lone Star Refining", sector: "Oil & Gas" },
  { id: "a4", ip: "203.0.113.201", port: 20000, protocol: "DNP3", location: "Ukraine", org: "Kyiv Regional Substation", sector: "Energy" },
  { id: "a5", ip: "198.51.100.66", port: 2404, protocol: "IEC-104", location: "Taiwan", org: "Taipei Telecom Backbone", sector: "Telecommunications" },
  { id: "a6", ip: "192.0.2.144", port: 1911, protocol: "Niagara Fox", location: "Saudi Arabia", org: "Riyadh Municipal SCADA", sector: "Utilities" },
];

export type ThreatBrief = {
  asset: OsintAsset;
  summary: string;
  priority: "P1 - CRITICAL" | "P2 - HIGH" | "P3 - MONITOR";
  sources: { url: string; title: string }[];
  generatedAt: string;
};

// ICS/SCADA protocol fingerprints — used to label Censys hits.
const PROTOCOL_BY_PORT: Record<number, { protocol: string; sector: string }> = {
  502: { protocol: "Modbus", sector: "Industrial Control" },
  102: { protocol: "Siemens S7", sector: "Industrial Control" },
  44818: { protocol: "EtherNet/IP", sector: "Industrial Control" },
  20000: { protocol: "DNP3", sector: "Energy" },
  2404: { protocol: "IEC-104", sector: "Energy" },
  1911: { protocol: "Niagara Fox", sector: "Building Automation" },
  4911: { protocol: "Niagara Fox", sector: "Building Automation" },
  47808: { protocol: "BACnet", sector: "Building Automation" },
  789: { protocol: "Red Lion Crimson", sector: "Industrial Control" },
  9600: { protocol: "OMRON FINS", sector: "Industrial Control" },
  5006: { protocol: "MELSEC-Q", sector: "Industrial Control" },
  1962: { protocol: "PCWorx", sector: "Industrial Control" },
};

// Default Censys query: ICS/SCADA services exposed to the public internet.
const DEFAULT_CENSYS_QUERY =
  "services.service_name: {MODBUS, S7, DNP3, IEC_60870_5_104, FOX, BACNET, ETHERNET_IP}";

type CensysHit = {
  ip?: string;
  location?: { country?: string; province?: string; city?: string };
  autonomous_system?: { name?: string };
  services?: Array<{
    port?: number;
    service_name?: string;
    extended_service_name?: string;
  }>;
};

function normalizeCensys(hits: CensysHit[]): OsintAsset[] {
  const out: OsintAsset[] = [];
  for (const h of hits) {
    if (!h.ip || !h.services?.length) continue;
    // Prefer ICS services; fall back to first service.
    const svc =
      h.services.find((s) => s.port && PROTOCOL_BY_PORT[s.port]) ?? h.services[0];
    const port = svc?.port ?? 0;
    const fingerprint = PROTOCOL_BY_PORT[port];
    const protocol =
      fingerprint?.protocol ??
      svc?.extended_service_name ??
      svc?.service_name ??
      "Unknown";
    const sector = fingerprint?.sector ?? "Infrastructure";
    const loc = [h.location?.city, h.location?.province, h.location?.country]
      .filter(Boolean)
      .join(", ") || "Unknown";
    out.push({
      id: `${h.ip}:${port}`,
      ip: h.ip,
      port,
      protocol,
      location: loc,
      org: h.autonomous_system?.name ?? "Unknown operator",
      sector,
    });
  }
  return out;
}

export type AssetFeed = {
  assets: OsintAsset[];
  source: "censys" | "mock";
  query: string;
  nextCursor?: string;
  pageSize: number;
  error?: string;
};

const PAGE_SIZE = 25;

export const listExposedAssets = createServerFn({ method: "GET" })
  .inputValidator((input?: { query?: string; cursor?: string }) => input ?? {})
  .handler(async ({ data }): Promise<AssetFeed> => {
    const query = data.query?.trim() || DEFAULT_CENSYS_QUERY;
    const cursor = data.cursor?.trim() || undefined;
    const apiKey = process.env.CENSYS_API_KEY;
    if (!apiKey) {
      return {
        assets: MOCK_ASSETS,
        source: "mock",
        query,
        pageSize: PAGE_SIZE,
        error: "Missing CENSYS_API_KEY",
      };
    }
    try {
      const res = await fetch("https://api.platform.censys.io/v3/global/search/query", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query,
          page_size: PAGE_SIZE,
          ...(cursor ? { cursor } : {}),
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        console.error(`Censys error [${res.status}]: ${body}`);
        return {
          assets: MOCK_ASSETS,
          source: "mock",
          query,
          pageSize: PAGE_SIZE,
          error: `Censys request failed [${res.status}] — showing mock feed`,
        };
      }
      const json = (await res.json()) as {
        result?: {
          hits?: CensysHit[];
          next_page_token?: string;
          nextCursor?: string;
          links?: { next?: string };
        };
        hits?: CensysHit[];
        next_page_token?: string;
        nextCursor?: string;
      };
      const hits = json.result?.hits ?? json.hits ?? [];
      const nextCursor =
        json.result?.nextCursor ||
        json.result?.next_page_token ||
        json.result?.links?.next ||
        json.nextCursor ||
        json.next_page_token ||
        undefined;
      const assets = normalizeCensys(hits);
      if (!assets.length && !cursor) {
        return {
          assets: MOCK_ASSETS,
          source: "mock",
          query,
          pageSize: PAGE_SIZE,
          error: "Censys returned no hits — showing mock feed",
        };
      }
      return { assets, source: "censys", query, nextCursor, pageSize: PAGE_SIZE };
    } catch (err) {
      console.error("Censys ingestion failed", err);
      return {
        assets: MOCK_ASSETS,
        source: "mock",
        query,
        pageSize: PAGE_SIZE,
        error: (err as Error).message,
      };
    }
  });

export const analyzeAsset = createServerFn({ method: "POST" })
  .inputValidator((input: { asset: OsintAsset }) => input)
  .handler(async ({ data }): Promise<ThreatBrief> => {
    const asset = data.asset;

    const apiKey = process.env.TAVILY_API_KEY;
    if (!apiKey) throw new Error("Missing TAVILY_API_KEY");

    const query = `Active cyber threats, state-sponsored attacks, APT groups, or malware campaigns targeting ${asset.protocol} systems or ${asset.sector} infrastructure in ${asset.location} in the last 30 days. Include specific threat actor groups and recent CVEs.`;

    const res = await fetch("https://api.tavily.com/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        api_key: apiKey,
        query,
        search_depth: "advanced",
        include_answer: true,
        max_results: 5,
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      console.error(`Tavily error [${res.status}]: ${body}`);
      throw new Error(`Tavily request failed [${res.status}]`);
    }

    const tavily = (await res.json()) as {
      answer?: string;
      results?: { url: string; title: string }[];
    };

    const answer = (tavily.answer ?? "No strategic intelligence found.").toString();
    const lower = answer.toLowerCase();
    let priority: ThreatBrief["priority"] = "P3 - MONITOR";
    if (/(apt|state-sponsored|sandworm|critical cve|zero-day|actively exploit)/.test(lower)) {
      priority = "P1 - CRITICAL";
    } else if (/(malware|vulnerability|cve-|ransomware|campaign)/.test(lower)) {
      priority = "P2 - HIGH";
    }

    return {
      asset,
      summary: answer,
      priority,
      sources: (tavily.results ?? []).map((r) => ({ url: r.url, title: r.title })),
      generatedAt: new Date().toISOString(),
    };
  });

// ─────────────────────────────────────────────────────────────
// OSINT Framework recon toolkit
// Sources https://github.com/lockfale/osint-framework — a curated
// hierarchical registry of investigation tools. We fetch the JSON,
// flatten it, and surface entries relevant to infrastructure recon.
// ─────────────────────────────────────────────────────────────

export type ReconTool = {
  name: string;
  url: string;
  category: string;
  description?: string;
  pricing?: string;
  api?: boolean;
  registration?: boolean;
  deprecated?: boolean;
};

type ArfNode = {
  name: string;
  type: "folder" | "url";
  url?: string;
  description?: string;
  pricing?: string;
  api?: boolean;
  registration?: boolean;
  deprecated?: boolean;
  children?: ArfNode[];
};

const ARF_URL =
  "https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json";

// Categories in OSINT Framework relevant to cyber-physical / infra recon.
// Matched against the top-level branch name.
const INFRA_BRANCHES = new Set([
  "IP & MAC Address",
  "Domain Name",
  "Malicious File Analysis",
  "Compliance & Risk Intelligence",
  "Dark Web",
  "Search Engines",
  "Tools",
  "Archives",
]);

let arfCache: { at: number; tools: ReconTool[] } | null = null;
const ARF_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

function flatten(node: ArfNode, trail: string[], out: ReconTool[]) {
  if (node.type === "folder") {
    for (const c of node.children ?? []) flatten(c, [...trail, node.name], out);
    return;
  }
  if (!node.url) return;
  // trail = [root, branch, ...subfolders]; keep "Branch > Subfolder".
  const branch = trail[1];
  if (!branch || !INFRA_BRANCHES.has(branch)) return;
  const category = trail.slice(1).join(" > ");
  out.push({
    name: node.name,
    url: node.url,
    category,
    description: node.description,
    pricing: node.pricing,
    api: node.api,
    registration: node.registration,
    deprecated: node.deprecated,
  });
}

async function loadArf(): Promise<ReconTool[]> {
  if (arfCache && Date.now() - arfCache.at < ARF_TTL_MS) return arfCache.tools;
  const res = await fetch(ARF_URL);
  if (!res.ok) throw new Error(`OSINT Framework fetch failed [${res.status}]`);
  const root = (await res.json()) as ArfNode;
  const tools: ReconTool[] = [];
  flatten(root, [], tools);
  arfCache = { at: Date.now(), tools };
  return tools;
}

export type ReconToolkit = {
  asset: OsintAsset;
  groups: { category: string; tools: ReconTool[] }[];
  total: number;
};

// Category priorities per asset context.
const SECTOR_CATEGORY_BOOST: Record<string, string[]> = {
  "Industrial Control": ["IP & MAC Address", "Tools", "Malicious File Analysis"],
  Energy: ["IP & MAC Address", "Compliance & Risk Intelligence", "Tools"],
  "Building Automation": ["IP & MAC Address", "Tools"],
  Infrastructure: ["IP & MAC Address", "Domain Name", "Tools"],
};

export const getReconToolkit = createServerFn({ method: "POST" })
  .inputValidator((input: { asset: OsintAsset }) => input)
  .handler(async ({ data }): Promise<ReconToolkit> => {
    const asset = data.asset;
    const all = await loadArf();
    const active = all.filter((t) => !t.deprecated);

    const boosted = new Set(
      SECTOR_CATEGORY_BOOST[asset.sector] ?? [
        "IP & MAC Address",
        "Domain Name",
        "Tools",
      ],
    );

    // Group by category, prioritized branches first.
    const byCat = new Map<string, ReconTool[]>();
    for (const t of active) {
      const arr = byCat.get(t.category) ?? [];
      arr.push(t);
      byCat.set(t.category, arr);
    }

    const groups = Array.from(byCat.entries())
      .map(([category, tools]) => ({
        category,
        tools: tools.sort((a, b) => a.name.localeCompare(b.name)),
      }))
      .sort((a, b) => {
        const ab = boosted.has(a.category.split(" > ")[0]) ? 0 : 1;
        const bb = boosted.has(b.category.split(" > ")[0]) ? 0 : 1;
        if (ab !== bb) return ab - bb;
        return a.category.localeCompare(b.category);
      });

    return { asset, groups, total: active.length };
  });