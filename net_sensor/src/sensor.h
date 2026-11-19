#pragma once
// Packet dispatch: DNS -> name cache + DNS events; TLS/QUIC -> flow tracker.
// Single-threaded by design; all timing comes from packet timestamps.

#include "config.h"
#include "dns.h"
#include "flow.h"
#include "indicators.h"
#include "output.h"

#include <unordered_map>

struct CaptureStats {          // filled in by main() for live captures
    bool     valid = false;
    uint64_t received = 0, dropped = 0, if_dropped = 0;
};

class Sensor {
public:
    Sensor(const Indicators& ind, const SensorConfig& cfg, Output& out);

    void on_frame(const uint8_t* data, size_t caplen, int dlt, Ts ts);
    // Advance timers without a packet (live capture idle periods).
    void advance(Ts now);
    // Flush all flows (end of file / shutdown).
    void shutdown();
    void emit_stats(const CaptureStats& cs);

    Ts now() const { return now_; }

private:
    void on_dns(const ParsedPacket& p, Ts ts);

    const Indicators&   ind_;
    const SensorConfig& cfg_;
    Output&             out_;
    DnsCache            dns_;
    FlowTracker         tracker_;

    Ts now_ = 0, next_tick_ = 0, next_housekeeping_ = 0;

    struct DedupKey {
        IpAddr client;
        std::string name;
        bool operator==(const DedupKey& o) const { return client == o.client && name == o.name; }
    };
    struct DedupHash {
        size_t operator()(const DedupKey& k) const noexcept {
            return size_t(fnv1a(hash_ip(kFnvBasis, k.client), k.name.data(), k.name.size()));
        }
    };
    std::unordered_map<DedupKey, Ts, DedupHash> dns_seen_;

    uint64_t frames_ = 0, parsed_ = 0, dns_msgs_ = 0, dns_events_ = 0;
};
