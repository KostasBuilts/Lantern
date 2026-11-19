// Loads indicators.yaml + policy.yaml and hot-reloads them on change.
import { readFileSync, watch } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import YAML from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const CONFIG_DIR = join(here, "..", "config");

const state = { indicators: {}, policy: {}, domainIndex: new Map(), sanctioned: new Set() };

function buildDomainIndex(indicators) {
  const idx = new Map();
  for (const [category, domains] of Object.entries(indicators.categories || {})) {
    for (const d of domains) idx.set(d.toLowerCase(), category);
  }
  return idx;
}

function loadOne(name) {
  return YAML.parse(readFileSync(join(CONFIG_DIR, name), "utf8"));
}

export function loadConfig() {
  state.indicators = loadOne("indicators.yaml");
  state.policy = loadOne("policy.yaml");
  state.domainIndex = buildDomainIndex(state.indicators);
  state.sanctioned = new Set((state.indicators.sanctioned || []).map((d) => d.toLowerCase()));
  return state;
}

// Match a hostname against the catalog, honouring subdomains (api.x.ai matches x.ai entries too).
export function matchDomain(host) {
  if (!host) return null;
  host = host.toLowerCase().replace(/\.$/, "");
  if (state.domainIndex.has(host)) return state.domainIndex.get(host);
  const parts = host.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    const suffix = parts.slice(i).join(".");
    if (state.domainIndex.has(suffix)) return state.domainIndex.get(suffix);
  }
  return null;
}

export function isSanctioned(host) {
  if (!host) return false;
  host = host.toLowerCase().replace(/\.$/, "");
  if (state.sanctioned.has(host)) return true;
  const parts = host.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (state.sanctioned.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

export const config = state;

export function watchConfig(onChange) {
  try {
    watch(CONFIG_DIR, { persistent: false }, (_e, file) => {
      if (file && file.endsWith(".yaml")) {
        try {
          loadConfig();
          onChange?.();
          console.log(`[config] reloaded (${file})`);
        } catch (err) {
          console.error("[config] reload failed:", err.message);
        }
      }
    });
  } catch {
    /* watch is best-effort */
  }
}
