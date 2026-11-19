#pragma once
// Tunables. Defaults are the values used by the CLI.

#include "common.h"

#include <bitset>

// Behavioural detector for LLM token streaming. A "burst" is a run of
// server->client application data with no gap longer than burst_gap.
struct DetectorConfig {
    double   threshold      = 0.70;          // alert when a qualifying burst scores >= this
    Ts       burst_gap      = 1500 * kMs;    // silence that ends a burst
    Ts       coalesce       = 1 * kMs;       // packets closer than this count as one event
    Ts       request_window = 30 * kSec;     // a request this recent "prompts" the burst
    size_t   request_min    = 120;           // c2s payload >= this is a request, not a control frame
    size_t   small_max      = 600;           // s2c payload <= this counts as a "token" packet

    // Gates a burst must pass before it can alert.
    uint32_t min_events      = 12;
    Ts       min_duration    = 1 * kSec;
    Ts       max_duration    = 300 * kSec;   // never-ending small-packet feeds are not chat replies
    Ts       min_median_gap  = 4 * kMs;      // faster than this is bulk transfer
    Ts       max_median_gap  = 500 * kMs;
    double   min_small_ratio = 0.5;
    double   max_up_down     = 0.5;          // client bytes during the burst / server bytes
};

struct SensorConfig {
    std::bitset<65536> service_ports;        // TLS (TCP) and QUIC (UDP) ports to track
    DetectorConfig det;

    bool     verbose            = false;     // emit every hello and every flow_end
    uint64_t upload_alert_bytes = 1 << 20;   // DLP: client->AI bytes in one flow (0 = off)

    Ts tcp_idle_timeout  = 300 * kSec;       // established flows (HTTP/2 keeps connections long)
    Ts tcp_embryonic     = 30 * kSec;        // flows that never carried data
    Ts udp_idle_timeout  = 120 * kSec;
    Ts closed_linger     = 5 * kSec;         // after FIN/RST
    Ts dns_dedup_window  = 300 * kSec;       // repeat DNS events per (client, name)

    size_t max_flows = 250000;

    SensorConfig() {
        service_ports.set(443);
        service_ports.set(8443);
        service_ports.set(4443);
    }
};
