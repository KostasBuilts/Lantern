"""Load and hot-reload indicators.yaml and policy.yaml."""
from __future__ import annotations
import os, threading, time
import yaml

CONFIG_DIR = os.environ.get("LANTERN_CONFIG", os.path.join(os.path.dirname(__file__), "..", "config"))

_DEFAULT_POLICY = {
    "stream_score_threshold": 0.70,
    "risk_window_hours": 24,
    "retention_hours": 72,
    "weights": {"shadow_domain": 15, "high_stream_unknown": 25, "local_ai": 30, "sensitive_egress": 40},
    "tiers": {"sanctioned": "allow", "shadow_domain": "coach", "high_stream": "redact",
              "local_ai": "block", "sensitive": "block"},
    "override_allowed": ["redact", "coach"],
    "dedup_window_seconds": 300,
}


class Config:
    """Thread-safe holder; reload() re-reads the YAML files if they changed."""
    def __init__(self):
        self._lock = threading.Lock()
        self.policy = dict(_DEFAULT_POLICY)
        self.indicators = {"sanctioned": [], "categories": {}}
        self._domain_index: dict[str, str] = {}   # domain -> category
        self._sanctioned: set[str] = set()
        self._mtimes: dict[str, float] = {}
        self.reload(force=True)

    def _path(self, name): return os.path.abspath(os.path.join(CONFIG_DIR, name))

    def reload(self, force=False):
        with self._lock:
            changed = False
            for name in ("indicators.yaml", "policy.yaml"):
                p = self._path(name)
                try:
                    mt = os.path.getmtime(p)
                except OSError:
                    continue
                if force or self._mtimes.get(p) != mt:
                    self._mtimes[p] = mt
                    changed = True
                    with open(p) as f:
                        data = yaml.safe_load(f) or {}
                    if name == "policy.yaml":
                        merged = dict(_DEFAULT_POLICY)
                        merged.update(data)
                        self.policy = merged
                    else:
                        self.indicators = data
            if changed:
                self._reindex()
            return changed

    def _reindex(self):
        idx = {}
        for cat, domains in (self.indicators.get("categories") or {}).items():
            for d in domains or []:
                idx[d.lower()] = cat
        self._domain_index = idx
        self._sanctioned = {d.lower() for d in (self.indicators.get("sanctioned") or [])}

    # ---- lookups (used by the engine) ----
    def match_domain(self, host: str | None):
        """Return (category, is_sanctioned) for a hostname, matching the registrable domain."""
        if not host:
            return (None, False)
        h = host.lower().rstrip(".")
        sanct = self._is_sanctioned(h)
        cat = None
        parts = h.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self._domain_index:
                cat = self._domain_index[cand]
                break
        return (cat, sanct)

    def _is_sanctioned(self, h: str):
        parts = h.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in self._sanctioned:
                return True
        return h in self._sanctioned

    def weight(self, key): return int((self.policy.get("weights") or {}).get(key, 0))
    def tier_action(self, tier): return (self.policy.get("tiers") or {}).get(tier, "observe")
    def get(self, key, default=None): return self.policy.get(key, default)

    def agent_view(self):
        """What GET /policy returns to the endpoint agents."""
        with self._lock:
            return {
                "version": int(max(self._mtimes.values()) if self._mtimes else 0),
                "stream_score_threshold": self.policy.get("stream_score_threshold"),
                "weights": self.policy.get("weights"),
                "tiers": self.policy.get("tiers"),
                "sanctioned": sorted(self._sanctioned),
                "blocked_categories": sorted((self.indicators.get("categories") or {}).keys()),
                "override_allowed": self.policy.get("override_allowed"),
            }


config = Config()


def start_watcher(interval=60):
    def loop():
        while True:
            time.sleep(interval)
            try:
                config.reload()
            except Exception:
                pass
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t
