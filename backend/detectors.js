// Lantern detector library (JS port of the tested Python reference).
// scan(text) -> [Hit]; redact(text) -> { text, mapping }.
// Raw values never leave: a Hit carries a mask + hash for logs, not the value.
import { createHash } from "node:crypto";

function sha16(s) { return createHash("sha256").update(s).digest("hex").slice(0, 16); }
function mask(raw, type) {
  if (type === "PERSON" || type === "ADDRESS") return raw[0] + "***";      // the tail of a name would leak it
  if (type === "EMAIL") return "***@" + raw.split("@")[1];
  return "****" + raw.replace(/\s/g, "").slice(-4);
}

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

// Personal data without a checksum: contact details, street addresses, and names
// that follow a cue ("my client ...", "Mr ...", "κ. ..."). The LLM judges context,
// but only what these find can be redacted.
const RE_EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;
const RE_PHONE = [
  /(?<![\d+])(?:(?:\+|00)30[ -]?)?(?:69\d|2\d\d)[ -]?\d{3}[ -]?\d{4}(?!\d)/g,             // Greek mobile / landline
  /(?<![\d+])(?:\+|00)[1-9]\d{0,2}[ -]?(?:\(?\d{1,4}\)?[ -]?){2,4}\d{2,4}(?!\d)/g,          // international, with + or 00
  /(?<=(?<!\p{L})(?:phone|tel|mobile|cell|call|κινητ|τηλ)\S*\.?:?\s*(?:on |at |no\.? )?)\d[\d -]{5,14}\d(?!\d)/giu,   // cued
];
const W = "\\p{L}[\\p{L}'.-]*";
const STREET = "(?:str(?:eet)?|st|ave(?:nue)?|road|rd|blvd|boulevard|lane|ln|drive|dr|square|sq|odos|οδός|οδ|λεωφ(?:όρος)?|πλατεία)";
const RE_ADDRESS = [
  new RegExp(`(?<![\\p{L}\\d])\\d{1,4}[a-zα-ω]?,?\\s+((?:${W}\\s+){1,3})${STREET}(?!\\p{L})\\.?`, "giu"),        // 24 Spooner Str.
  new RegExp(`(?<!\\p{L})((?:${W}\\s+){1,3})${STREET}\\.?\\s+\\d{1,4}[a-zα-ω]?(?![\\p{L}\\d])`, "giu"),         // Ermou Str 24
  new RegExp(`(?<!\\p{L})(?:odos|οδός|οδ\\.|λεωφ\\.|λεωφόρος)\\s+((?:${W}\\s+){1,3})\\d{1,4}(?![\\p{L}\\d])`, "giu"), // οδός Ερμού 24
];
const RE_PERSON = /(?<!\p{L})(?:(?:my|our|your|his|her|their)\s+(?:client|customer|patient|tenant|colleague|employee|lawyer|doctor)|(?:client|customer|patient|employee)\s*:|mrs?\.?|ms\.?|named|name(?:\s*(?:is|:))?|κ(?:ος|α)?\.|πελάτη[ςσ]?|ασθενή[ςσ]?)\s+(\p{L}[\p{L}'-]+)(?:\s+(\p{L}[\p{L}'-]+))?/giud;
const STOP = new Set(("a an the this that these those is was are be been has have had will would can could should " +
  "who which what when where why how about above after before from for with without to on at in into of by and or but " +
  "not no so if then than my our your his her their its it me us them he she they we you i him " +
  "wants want asked asks said says sent sends called calls lives lived just also still please " +
  "data record records details info information email emails phone number account accounts address list name names " +
  "side library app code request requests id ids support service team company").split(" "));
const allNamey = (s) => s.trim().split(/\s+/).every((w) => !STOP.has(w.toLowerCase().replace(/\.$/, "")));

function hasCtx(text, start, rx, win = 40) { return rx.test(text.slice(Math.max(0, start - win), start)); }
function overlaps(a, hits) { return hits.some((o) => !(a.end <= o.start || a.start >= o.end)); }
function push(hits, type, m, conf, raw, start = m.index) {
  const h = { type, start, end: start + raw.length, confidence: conf, masked: mask(raw, type), value_hash: sha16(raw) };
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
  RE_EMAIL.lastIndex = 0;
  while ((m = RE_EMAIL.exec(text))) push(hits, "EMAIL", m, 0.95, m[0]);
  for (const rx of RE_PHONE) { rx.lastIndex = 0; while ((m = rx.exec(text))) push(hits, "PHONE", m, 0.8, m[0]); }
  for (const rx of RE_ADDRESS) {
    rx.lastIndex = 0;
    while ((m = rx.exec(text))) if (allNamey(m[1])) push(hits, "ADDRESS", m, 0.7, m[0].replace(/[\s,]+$/, ""));
  }
  RE_PERSON.lastIndex = 0;
  while ((m = RE_PERSON.exec(text))) {
    if (STOP.has(m[1].toLowerCase())) continue;
    if (/name$/i.test(m[0].slice(0, m.indices[1][0] - m.index).trim()) && !/^\p{Lu}/u.test(m[1])) continue;   // bare "name": only before a capital
    const both = m[2] && !STOP.has(m[2].toLowerCase());
    const start = m.indices[1][0], end = both ? m.indices[2][1] : m.indices[1][1];
    push(hits, "PERSON", m, 0.7, text.slice(start, end), start);
  }
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
