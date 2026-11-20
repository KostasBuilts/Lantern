// Helpers shared by the dashboard (app.js) and the AI gateway page (gateway.js).

export const $ = (s, r = document) => r.querySelector(s);
export const el = (t, props = {}, kids = []) => {
  const n = document.createElement(t);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;        // always textContent — labels are untrusted
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of [].concat(kids)) n.append(c);
  return n;
};
export const api = (p) => fetch(p).then((r) => r.json());
export const cssvar = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const pad = (n) => String(n).padStart(2, "0");
export const hhmm = (d) => pad(d.getHours()) + ":" + pad(d.getMinutes());
export function ago(iso) {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return Math.floor(s) + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}
export const ACTION_COLOR = { allow: "--good", warn: "--warning", redact: "--serious", block: "--critical" };

// Light/dark toggle, remembered per browser.
export function initTheme(onChange = () => {}) {
  try { const saved = localStorage.getItem("lantern-theme"); if (saved) document.documentElement.setAttribute("data-theme", saved); } catch {}
  $("#themeBtn").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("lantern-theme", next); } catch {}
    onChange();
  });
}

// Status pill for a model: green when it answers, red when it doesn't (decisions then fall back to rules).
const MODEL_STATE = { ready: "ready", starting: "starting…", unreachable: "not answering", off: "off" };
export function modelPill(node, label, s, fallback) {
  if (!node || !s) return;
  node.className = "pill " + (s.state === "ready" ? "live" : s.state === "starting" ? "" : "offline");
  const extra = s.state === "ready" || s.state === "starting" ? "" : ` · ${fallback}`;
  node.replaceChildren(el("span", { class: "live-dot" }),
    el("span", { class: "pill-text", text: `${label}: ${s.model} · ${MODEL_STATE[s.state] || s.state}${extra}` }));
}
