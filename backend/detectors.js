// Lantern detector library (JS port of the tested Python reference).
// scan(text) -> [Hit]; redact(text) -> { text, mapping }.
// Raw values never leave: a Hit carries a mask + hash for logs, not the value.
import { createHash } from "node:crypto";

function sha16(s) { return createHash("sha256").update(s).digest("hex").slice(0, 16); }
function mask(raw) { return "****" + raw.replace(/\s/g, "").slice(-4); }

// ---------- checksums ----------
export function luhnOk(digits) {
  let total = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    total += d; alt = !alt;
  }
  return total % 10 === 0;
}

export function afmOk(s) {                       // Greek tax id: 9 digits, weighted mod-11
  if (!/^\d{9}$/.test(s) || s === "000000000") return false;
  let total = 0;
  for (let i = 0; i < 8; i++) total += (s.charCodeAt(i) - 48) * 2 ** (8 - i);
  return (total % 11) % 10 === (s.charCodeAt(8) - 48);
}

function validDate(dd, mm, yy) {
  for (const c of [1900, 2000]) {
    const d = new Date(Date.UTC(c + yy, mm - 1, dd));
    if (d.getUTCFullYear() === c + yy && d.getUTCMonth() === mm - 1 && d.getUTCDate() === dd) return true;
  }
  return false;
}
export function amkaOk(s) {                       // Greek social security: 11 digits, Luhn + DDMMYY
  if (!/^\d{11}$/.test(s)) return false;
  if (!validDate(+s.slice(0, 2), +s.slice(2, 4), +s.slice(4, 6))) return false;
  return luhnOk(s);
}

const IBAN_LEN = { GR: 27, DE: 22, FR: 27, IT: 27, ES: 24, GB: 22, NL: 18, CY: 28, BG: 22 };
export function ibanOk(raw) {
  const s = raw.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s) || s.length < 15 || s.length > 34) return false;
  if (IBAN_LEN[s.slice(0, 2)] && s.length !== IBAN_LEN[s.slice(0, 2)]) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;                                    // mod-97 over a long digit string
  for (const ch of moved) rem = (rem * (ch >= "0" && ch <= "9" ? 10 : 100) + parseInt(ch, 36)) % 97;
  return rem === 1;
}

export function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const c of Object.values(freq)) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

// ---------- patterns ----------
const CTX_AFM = /(Α\.?Φ\.?Μ\.?|AFM|ΑΦΜ|tax\s*id|VAT)/i;
const CTX_AMKA = /(ΑΜΚΑ|AMKA|social\s*security)/i;
const SECRETS = [
  ["anthropic", /sk-ant-[A-Za-z0-9_-]{20,}/g],
  ["openai", /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g],
  ["google", /AIza[0-9A-Za-z_-]{35}/g],
  ["github", /(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})/g],
  ["aws", /\bAKIA[0-9A-Z]{16}\b/g],
  ["privkey", /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
];
const RE_IBAN = /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b/g;
const RE_CARD = /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g;
const RE_TOKEN = /[A-Za-z0-9+/=_-]{24,}/g;
const RE_9 = /(?<!\d)\d{9}(?!\d)/g;
const RE_11 = /(?<!\d)\d{11}(?!\d)/g;

function hasCtx(text, start, rx, win = 40) { return rx.test(text.slice(Math.max(0, start - win), start)); }
function overlaps(a, hits) { return hits.some((o) => !(a.end <= o.start || a.start >= o.end)); }
function push(hits, type, m, conf, raw) {
  const h = { type, start: m.index, end: m.index + raw.length, confidence: conf, masked: mask(raw), value_hash: sha16(raw) };
  if (!overlaps(h, hits)) hits.push(h);
}

export function scan(text) {
  if (!text) return [];
  const hits = [];
  let m;
  RE_IBAN.lastIndex = 0;
  while ((m = RE_IBAN.exec(text))) if (ibanOk(m[0])) push(hits, "IBAN", m, 0.99, m[0]);
  for (const [, rx] of SECRETS) { rx.lastIndex = 0; while ((m = rx.exec(text))) push(hits, "SECRET", m, 0.95, m[0]); }
  RE_TOKEN.lastIndex = 0;
  while ((m = RE_TOKEN.exec(text))) {
    const tok = m[0], isHex = /^[0-9a-fA-F]+$/.test(tok), limit = isHex ? 3.0 : 4.5;
    if ((!isHex || tok.length >= 32) && entropy(tok) > limit) push(hits, "SECRET", m, 0.6, tok);
  }
  RE_CARD.lastIndex = 0;
  while ((m = RE_CARD.exec(text))) {
    const digits = m[0].replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits))
      push(hits, "CARD", m, "3456".includes(digits[0]) ? 0.9 : 0.6, m[0]);
  }
  RE_11.lastIndex = 0;
  while ((m = RE_11.exec(text))) if (amkaOk(m[0])) push(hits, "AMKA", m, hasCtx(text, m.index, CTX_AMKA) ? 0.95 : 0.5, m[0]);
  RE_9.lastIndex = 0;
  while ((m = RE_9.exec(text))) if (afmOk(m[0])) push(hits, "AFM", m, hasCtx(text, m.index, CTX_AFM) ? 0.95 : 0.3, m[0]);
  return hits.sort((a, b) => a.start - b.start);
}

// Replace hits with stable tags; same raw value -> same tag within one call.
export function redact(text, minConf = 0.5) {
  const seen = new Map(), counters = {}, mapping = {};
  let out = "", pos = 0;
  for (const h of scan(text)) {
    if (h.confidence < minConf) continue;
    const raw = text.slice(h.start, h.end);
    if (!seen.has(raw)) {
      counters[h.type] = (counters[h.type] || 0) + 1;
      const tag = `[${h.type}-${counters[h.type]}]`;
      seen.set(raw, tag); mapping[tag] = h.masked;
    }
    out += text.slice(pos, h.start) + seen.get(raw);
    pos = h.end;
  }
  return { text: out + text.slice(pos), mapping };
}

// Summarise hits by type for logging (types + counts, never values).
export function summarise(hits) {
  const by = {};
  for (const h of hits) by[h.type] = (by[h.type] || 0) + 1;
  return Object.entries(by).map(([type, count]) => ({ type, count }));
}
