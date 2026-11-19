#include "indicators.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace {

// Walk `host` and its parent domains, most specific first.
template <typename Fn>
bool for_each_suffix(const std::string& host, Fn&& fn) {
    if (host.empty()) return false;
    if (fn(host)) return true;
    for (size_t dot = host.find('.'); dot != std::string::npos; dot = host.find('.', dot + 1))
        if (dot + 1 < host.size() && fn(host.substr(dot + 1))) return true;
    return false;
}

bool looks_like_ip_or_cidr(const std::string& s) {
    return !s.empty() && (s.find(':') != std::string::npos || s.find('/') != std::string::npos ||
                          std::all_of(s.begin(), s.end(),
                                      [](char c) { return std::isdigit((unsigned char)c) || c == '.'; }));
}

}  // namespace

std::string normalize_host(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    while (!s.empty() && s.back() == '.') s.pop_back();
    if (s.rfind("*.", 0) == 0) s.erase(0, 2);
    return s;
}

Indicators::Indicators() {
    // Cloudflare's ECH public name: with ECH the visible SNI is this, not the site.
    ech_outer_.insert("cloudflare-ech.com");
}

void Indicators::add_category_domain(const std::string& category, const std::string& domain) {
    const std::string d = normalize_host(domain);
    if (d.empty()) return;
    categories_.insert(category);
    domain_category_[d] = category;
}

void Indicators::add_ech_outer(const std::string& domain) {
    const std::string d = normalize_host(domain);
    if (!d.empty()) ech_outer_.insert(d);
}

bool Indicators::add_sanctioned(const std::string& entry) {
    if (looks_like_ip_or_cidr(entry)) {
        Cidr c;
        if (!parse_cidr(entry, c)) return false;
        sanctioned_nets_.push_back(c);
        return true;
    }
    const std::string d = normalize_host(entry);
    if (d.empty()) return false;
    sanctioned_domains_.insert(d);
    return true;
}

bool Indicators::parse_cidr(const std::string& s, Cidr& out) {
    const size_t slash = s.find('/');
    const std::string addr = s.substr(0, slash);
    unsigned char buf[16] = {0};
    if (inet_pton(AF_INET, addr.c_str(), buf) == 1) {
        out.net = IpAddr::from4(buf);
        out.prefix = 32;
    } else if (inet_pton(AF_INET6, addr.c_str(), buf) == 1) {
        out.net = IpAddr::from6(buf);
        out.prefix = 128;
    } else {
        return false;
    }
    if (slash != std::string::npos) {
        const std::string p = s.substr(slash + 1);
        if (p.empty() || p.size() > 3 || !std::all_of(p.begin(), p.end(), ::isdigit)) return false;
        const int prefix = std::stoi(p);
        if (prefix > out.prefix) return false;
        out.prefix = prefix;
    }
    return true;
}

bool Indicators::load(const std::string& path, std::string& err) {
    try {
        const YAML::Node root = YAML::LoadFile(path);
        if (!root.IsMap()) { err = "top level must be a mapping"; return false; }

        for (const auto& kv : root) {
            const std::string key = kv.first.as<std::string>();
            const YAML::Node& val = kv.second;
            if (key == "sanctioned" || key == "ech_outer_names") {
                if (val.IsNull()) continue;
                if (!val.IsSequence()) { err = "'" + key + "' must be a list"; return false; }
                for (const auto& n : val) {
                    const std::string e = n.as<std::string>();
                    if (key == "ech_outer_names") {
                        add_ech_outer(e);
                    } else if (!add_sanctioned(e)) {
                        err = "invalid sanctioned entry '" + e + "'";
                        return false;
                    }
                }
            } else if (key == "categories") {
                if (!val.IsMap()) { err = "'categories' must be a mapping of name -> list"; return false; }
                for (const auto& cat : val) {
                    const std::string name = cat.first.as<std::string>();
                    if (cat.second.IsNull()) continue;
                    if (!cat.second.IsSequence()) {
                        err = "category '" + name + "' must be a list of domains";
                        return false;
                    }
                    for (const auto& d : cat.second) {
                        const std::string dom = d.as<std::string>();
                        if (looks_like_ip_or_cidr(dom))
                            std::fprintf(stderr, "[indicators] warning: '%s' in category '%s' looks "
                                                 "like an address; only domains are matched\n",
                                         dom.c_str(), name.c_str());
                        add_category_domain(name, dom);
                    }
                }
            } else {
                std::fprintf(stderr, "[indicators] warning: ignoring unknown key '%s'\n", key.c_str());
            }
        }
        return true;
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

const std::string* Indicators::category_of(const std::string& host) const {
    const std::string* result = nullptr;
    for_each_suffix(normalize_host(host), [&](const std::string& s) {
        auto it = domain_category_.find(s);
        if (it == domain_category_.end()) return false;
        result = &it->second;
        return true;
    });
    return result;
}

bool Indicators::sanctioned_name(const std::string& host) const {
    return for_each_suffix(normalize_host(host),
                           [&](const std::string& s) { return sanctioned_domains_.count(s) > 0; });
}

bool Indicators::sanctioned_ip(const IpAddr& ip) const {
    for (const auto& c : sanctioned_nets_) {
        if (c.net.v6 != ip.v6) continue;
        const int full = c.prefix / 8, rem = c.prefix % 8;
        if (std::memcmp(c.net.b.data(), ip.b.data(), size_t(full)) != 0) continue;
        if (rem) {
            const uint8_t mask = uint8_t(0xFF << (8 - rem));
            if ((c.net.b[size_t(full)] & mask) != (ip.b[size_t(full)] & mask)) continue;
        }
        return true;
    }
    return false;
}

bool Indicators::is_ech_outer(const std::string& sni) const {
    return ech_outer_.count(normalize_host(sni)) > 0;
}
