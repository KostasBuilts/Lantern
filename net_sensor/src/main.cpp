// shadow-ai-sensor: passive detection of AI service use on a network tap or
// mirror port. See README.md.

#include "config.h"
#include "indicators.h"
#include "output.h"
#include "packet.h"
#include "sensor.h"

#include <getopt.h>
#include <grp.h>
#include <poll.h>
#include <pcap/pcap.h>
#include <pwd.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace {

volatile sig_atomic_t g_stop = 0;
pcap_t* g_handle = nullptr;

void on_signal(int) {
    g_stop = 1;
    if (g_handle) pcap_breakloop(g_handle);   // wakes a blocked pcap_next_ex
}

struct LoopCtx {
    Sensor* sensor;
    int     dlt;
};

void on_packet(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    auto* ctx = reinterpret_cast<LoopCtx*>(user);
    const Ts ts = Ts(hdr->ts.tv_sec) * kSec + Ts(hdr->ts.tv_usec);
    ctx->sensor->on_frame(pkt, hdr->caplen, ctx->dlt, ts);
}

Ts wall_now() {
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    return Ts(ts.tv_sec) * kSec + ts.tv_nsec / 1000;
}

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s -c indicators.yaml (-i IFACE | -r FILE) [options]\n"
        "       %s IFACE indicators.yaml          (legacy form)\n"
        "\n"
        "  -i, --interface IFACE   capture live (needs CAP_NET_RAW or root)\n"
        "  -r, --read FILE         analyse a pcap/pcapng file\n"
        "  -c, --config FILE       indicators YAML (required)\n"
        "  -j, --json              JSON-lines output (default: key=value text)\n"
        "  -t, --threshold X       behavioural alert threshold, 0..1 (default 0.70)\n"
        "  -p, --ports LIST        TLS/QUIC ports to watch (default 443,8443,4443)\n"
        "  -f, --filter EXPR       replace the generated BPF filter\n"
        "  -u, --upload-mb N       alert when one flow sends N MiB to an AI service (default 1, 0=off)\n"
        "  -B, --buffer-mb N       kernel capture buffer (default 64)\n"
        "  -s, --stats SECONDS     emit capture stats periodically (live)\n"
        "  -Z, --user USER         drop privileges to USER after opening the capture\n"
        "  -P, --no-promisc        don't put the interface in promiscuous mode\n"
        "  -v, --verbose           also log every ClientHello, burst and flow end\n"
        "  -h, --help\n",
        argv0, argv0);
}

bool parse_count(const char* s, long lo, long hi, long& out) {
    char* end = nullptr;
    errno = 0;
    out = std::strtol(s, &end, 10);
    return end != s && *end == '\0' && errno == 0 && out >= lo && out <= hi;
}

bool parse_ports(const char* s, std::bitset<65536>& out) {
    out.reset();
    std::string tok;
    for (const char* p = s;; ++p) {
        if (*p == ',' || *p == '\0') {
            if (tok.empty()) return false;
            char* end = nullptr;
            const long v = std::strtol(tok.c_str(), &end, 10);
            if (*end || v < 1 || v > 65535) return false;
            out.set(size_t(v));
            tok.clear();
            if (*p == '\0') break;
        } else {
            tok.push_back(*p);
        }
    }
    return out.any();
}

std::string build_filter(const std::bitset<65536>& ports, int dlt) {
    std::string plist;
    for (size_t i = 1; i < ports.size(); ++i) {
        if (!ports.test(i)) continue;
        if (!plist.empty()) plist += " or ";
        plist += "port " + std::to_string(i);
    }
    // DNS (for names), TLS over TCP, QUIC over UDP.
    const std::string base = "udp port 53 or ((tcp or udp) and (" + plist + "))";
    // Mirror/SPAN ports often deliver 802.1Q-tagged frames, which a plain
    // filter silently drops.
    if (dlt == DLT_EN10MB) return "(" + base + ") or (vlan and (" + base + "))";
    return base;
}

bool drop_privileges(const char* user) {
    errno = 0;
    const struct passwd* pw = getpwnam(user);
    if (!pw) {
        std::fprintf(stderr, "unknown user '%s'\n", user);
        return false;
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0 || setgid(pw->pw_gid) != 0 ||
        setuid(pw->pw_uid) != 0) {
        std::fprintf(stderr, "dropping privileges to '%s': %s\n", user, std::strerror(errno));
        return false;
    }
    if (setuid(0) == 0) {                       // must not be able to regain root
        std::fprintf(stderr, "privilege drop did not stick\n");
        return false;
    }
    return true;
}

pcap_t* open_live(const std::string& iface, int buffer_mb, bool promisc) {
    char err[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* h = pcap_create(iface.c_str(), err);
    if (!h) {
        std::fprintf(stderr, "pcap_create(%s): %s\n", iface.c_str(), err);
        return nullptr;
    }
    pcap_set_snaplen(h, 65535);
    pcap_set_promisc(h, promisc ? 1 : 0);
    pcap_set_timeout(h, 250);
    pcap_set_buffer_size(h, buffer_mb * 1024 * 1024);
    pcap_set_tstamp_precision(h, PCAP_TSTAMP_PRECISION_MICRO);
    const int rc = pcap_activate(h);
    if (rc < 0) {
        std::fprintf(stderr, "pcap_activate(%s): %s: %s\n", iface.c_str(), pcap_statustostr(rc),
                     pcap_geterr(h));
        pcap_close(h);
        return nullptr;
    }
    if (rc > 0)
        std::fprintf(stderr, "pcap_activate(%s) warning: %s: %s\n", iface.c_str(),
                     pcap_statustostr(rc), pcap_geterr(h));
    return h;
}

}  // namespace

int main(int argc, char** argv) {
    SensorConfig cfg;
    std::string iface, file, config, filter, user;
    bool json = false, promisc = true;
    int buffer_mb = 64;
    long stats_every = 0;

    static const struct option opts[] = {
        {"interface", required_argument, nullptr, 'i'}, {"read", required_argument, nullptr, 'r'},
        {"config", required_argument, nullptr, 'c'},    {"json", no_argument, nullptr, 'j'},
        {"threshold", required_argument, nullptr, 't'}, {"ports", required_argument, nullptr, 'p'},
        {"filter", required_argument, nullptr, 'f'},    {"upload-mb", required_argument, nullptr, 'u'},
        {"buffer-mb", required_argument, nullptr, 'B'}, {"stats", required_argument, nullptr, 's'},
        {"user", required_argument, nullptr, 'Z'},      {"no-promisc", no_argument, nullptr, 'P'},
        {"verbose", no_argument, nullptr, 'v'},         {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}};

    int c;
    while ((c = getopt_long(argc, argv, "i:r:c:jt:p:f:u:B:s:Z:Pvh", opts, nullptr)) != -1) {
        switch (c) {
        case 'i': iface = optarg; break;
        case 'r': file = optarg; break;
        case 'c': config = optarg; break;
        case 'j': json = true; break;
        case 't': {
            char* end = nullptr;
            cfg.det.threshold = std::strtod(optarg, &end);
            if (*end || cfg.det.threshold < 0 || cfg.det.threshold > 1) {
                std::fprintf(stderr, "threshold must be between 0 and 1\n");
                return 1;
            }
            break;
        }
        case 'p':
            if (!parse_ports(optarg, cfg.service_ports)) {
                std::fprintf(stderr, "bad port list '%s'\n", optarg);
                return 1;
            }
            break;
        case 'f': filter = optarg; break;
        case 'u': case 'B': case 's': {
            long v;
            if (!parse_count(optarg, 0, 1 << 20, v)) {
                std::fprintf(stderr, "-%c expects a non-negative integer, got '%s'\n", c, optarg);
                return 1;
            }
            if (c == 'u') cfg.upload_alert_bytes = uint64_t(v) << 20;
            else if (c == 'B') buffer_mb = int(std::max(1L, v));
            else stats_every = v;
            break;
        }
        case 'Z': user = optarg; break;
        case 'P': promisc = false; break;
        case 'v': cfg.verbose = true; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    // Legacy positional form: <iface> <indicators.yaml>
    if (iface.empty() && file.empty() && config.empty() && argc - optind == 2) {
        iface = argv[optind];
        config = argv[optind + 1];
    } else if (optind != argc) {
        usage(argv[0]);
        return 1;
    }
    if (config.empty() || iface.empty() == file.empty()) {
        usage(argv[0]);
        return 1;
    }

    // Line-buffered so alerts reach a pipe/collector immediately.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    Indicators ind;
    std::string err;
    if (!ind.load(config, err)) {
        std::fprintf(stderr, "[indicators] %s: %s\n", config.c_str(), err.c_str());
        return 2;
    }
    std::fprintf(stderr, "[sensor] %zu AI domains in %zu categories, %zu sanctioned entries\n",
                 ind.domain_count(), ind.category_count(), ind.sanctioned_count());

    const bool live = !iface.empty();
    pcap_t* h = nullptr;
    if (live) {
        h = open_live(iface, buffer_mb, promisc);
    } else {
        char e[PCAP_ERRBUF_SIZE] = {0};
        h = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_MICRO, e);
        if (!h) std::fprintf(stderr, "pcap_open_offline(%s): %s\n", file.c_str(), e);
    }
    if (!h) return 3;

    const int dlt = pcap_datalink(h);
    if (!link_type_supported(dlt)) {
        std::fprintf(stderr, "unsupported link type %s (%d)\n",
                     pcap_datalink_val_to_name(dlt) ? pcap_datalink_val_to_name(dlt) : "?", dlt);
        pcap_close(h);
        return 4;
    }

    if (filter.empty()) filter = build_filter(cfg.service_ports, dlt);
    struct bpf_program fp{};
    if (pcap_compile(h, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(h, &fp) < 0) {
        std::fprintf(stderr, "BPF filter '%s': %s\n", filter.c_str(), pcap_geterr(h));
        pcap_close(h);
        return 5;
    }
    pcap_freecode(&fp);

    if (!user.empty() && !drop_privileges(user.c_str())) {
        pcap_close(h);
        return 7;
    }

    g_handle = h;
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    std::fprintf(stderr, "[sensor] %s %s (link %s), filter: %s\n", live ? "capturing on" : "reading",
                 live ? iface.c_str() : file.c_str(), pcap_datalink_val_to_name(dlt), filter.c_str());

    Output out(json ? OutputFormat::Json : OutputFormat::Text, stdout);
    Sensor sensor(ind, cfg, out);

    auto capture_stats = [&]() {
        CaptureStats cs;
        struct pcap_stat ps{};
        if (live && pcap_stats(h, &ps) == 0) {
            cs.valid = true;
            cs.received = ps.ps_recv;
            cs.dropped = ps.ps_drop;
            cs.if_dropped = ps.ps_ifdrop;
        }
        return cs;
    };

    LoopCtx ctx{&sensor, dlt};
    int rc_exit = 0;
    if (live) {
        // Non-blocking dispatch + our own poll(): on Linux the pcap read
        // timeout never fires while the link is quiet, which would hold
        // back alerts (and flow expiry) until the next packet arrives.
        char e[PCAP_ERRBUF_SIZE] = {0};
        const int fd = pcap_get_selectable_fd(h);
        if (fd < 0 || pcap_setnonblock(h, 1, e) < 0) {
            std::fprintf(stderr, "cannot poll the capture: %s\n", e);
            pcap_close(h);
            return 3;
        }
        Ts next_stats = stats_every ? wall_now() + stats_every * kSec : 0;
        while (!g_stop) {
            const int n = pcap_dispatch(h, 4096, on_packet, reinterpret_cast<u_char*>(&ctx));
            if (n == PCAP_ERROR_BREAK) break;
            if (n < 0) {
                std::fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(h));
                rc_exit = 6;
                break;
            }
            if (n == 0) {
                struct pollfd pfd{fd, POLLIN, 0};
                poll(&pfd, 1, 250);                    // EINTR on SIGINT/SIGTERM is fine
            }
            // Timers run slightly behind the wall clock so packets still in
            // the kernel's ring buffer can't arrive "after" a burst closed.
            const Ts now = wall_now();
            sensor.advance(now - 500 * kMs);
            if (stats_every && now >= next_stats) {
                next_stats = now + stats_every * kSec;
                sensor.emit_stats(capture_stats());
            }
        }
        sensor.advance(wall_now());
    } else {
        for (;;) {
            const int n = pcap_dispatch(h, 4096, on_packet, reinterpret_cast<u_char*>(&ctx));
            if (n == 0 || n == PCAP_ERROR_BREAK || g_stop) break;   // end of file / signal
            if (n < 0) {
                std::fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(h));
                rc_exit = 6;
                break;
            }
        }
    }

    sensor.shutdown();
    const CaptureStats cs = capture_stats();
    sensor.emit_stats(cs);
    if (cs.valid && (cs.dropped || cs.if_dropped))
        std::fprintf(stderr, "[sensor] warning: %llu packets dropped by the kernel, %llu by the interface; "
                             "consider a larger -B buffer\n",
                     (unsigned long long)cs.dropped, (unsigned long long)cs.if_dropped);
    g_handle = nullptr;
    pcap_close(h);
    return rc_exit;
}
