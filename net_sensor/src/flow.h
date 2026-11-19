#pragma once
// Per-connection state: client/server orientation, ClientHello reassembly
// (TCP and QUIC), destination identity, and the LLM-streaming detector.

#include "common.h"
#include "config.h"
#include "dns.h"
#include "indicators.h"
#include "output.h"
#include "packet.h"
#include "tls.h"

#include <climits>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

// Summary of one server->client burst once it ends.
struct BurstResult {
    bool        qualifies = false;   // passed every gate
    const char* reject    = nullptr; // first gate that failed
    double      score     = 0;       // weighted feature score in [0,1]
    bool        prompted  = false;   // a client request preceded the burst
    uint32_t    pkts = 0, events = 0;
    double      duration_s = 0, small_ratio = 0, cadence = 0, median_gap_ms = 0;
    uint64_t    down_bytes = 0, up_bytes = 0, request_bytes = 0;
};

// Detects "prompt -> streamed reply": a client request followed by a burst of
// small, regularly spaced server records (one per token or few tokens), with
// the client mostly quiet meanwhile. Scored per burst, not per connection, so
// TLS handshakes, idle keep-alive time and unrelated requests on the same
// HTTP/2 connection don't pollute the features.
class StreamDetector {
public:
    explicit StreamDetector(const DetectorConfig& cfg) : cfg_(&cfg) {}

    // Feed one application-data packet (payload length on the wire). Returns
    // the result of a burst that this packet's arrival closed, if any.
    std::optional<BurstResult> on_data(bool c2s, size_t len, Ts t);
    // Close the open burst if the server has been quiet for burst_gap (or now, if force).
    std::optional<BurstResult> poll(Ts now, bool force);

    static constexpr double W_PROMPTED = 0.30;
    static constexpr double W_SMALL    = 0.30;
    static constexpr double W_CADENCE  = 0.25;
    static constexpr double W_DURATION = 0.15;

private:
    BurstResult close_burst();

    static constexpr Ts kNever = LLONG_MIN;
    static constexpr size_t kMaxGaps = 512;

    const DetectorConfig* cfg_;
    Ts       last_request_ = kNever;
    uint64_t pending_request_bytes_ = 0;

    bool     open_ = false, overlong_ = false, prompted_ = false;
    Ts       start_ = 0, last_pkt_ = 0, last_event_ = 0;
    uint32_t pkts_ = 0, small_ = 0, events_ = 0;
    uint64_t down_ = 0, up_ = 0, request_bytes_ = 0;
    std::vector<float> gaps_ms_;
};

struct TrackerStats {
    uint64_t flows_created = 0, flows_rejected = 0;
    uint64_t hellos_tcp = 0, hellos_quic = 0, hello_failures = 0, quic_initials = 0;
    uint64_t conn_events = 0, stream_alerts = 0, upload_alerts = 0;
};

class FlowTracker {
public:
    FlowTracker(const SensorConfig& cfg, const Indicators& ind, const DnsCache& dns, Output& out);
    ~FlowTracker();

    void on_tcp(const ParsedPacket& p, Ts ts);
    void on_quic(const ParsedPacket& p, Ts ts);   // UDP on a service port
    void tick(Ts now);                            // close quiet bursts, expire idle flows
    void shutdown(Ts now);                        // flush everything

    size_t active() const { return flows_.size(); }
    const TrackerStats& stats() const { return stats_; }

private:
    struct Flow;

    Flow* get_flow(const ParsedPacket& p, Ts ts);
    void  feed_tcp_hello(Flow& f, const ParsedPacket& p, Ts ts);
    void  feed_quic_initial(Flow& f, const ParsedPacket& p, Ts ts);
    void  on_hello(Flow& f, const TlsClientHello& ch, char transport, Ts ts);
    void  give_up_hello(Flow& f, Ts ts);
    void  account(Flow& f, bool c2s, size_t len, Ts ts);
    void  handle_burst(Flow& f, const BurstResult& r, Ts ts);
    void  resolve_identity(Flow& f, Ts ts);
    void  finish(Flow& f, Ts ts, const char* reason);
    void  add_flow_fields(Event& e, const Flow& f) const;

    const SensorConfig& cfg_;
    const Indicators&   ind_;
    const DnsCache&     dns_;
    Output&             out_;
    TrackerStats        stats_;
    std::unordered_map<FlowKey, std::unique_ptr<Flow>, FlowKeyHash> flows_;
};
