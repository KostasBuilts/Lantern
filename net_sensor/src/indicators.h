#pragma once
// Destination policy loaded from YAML: AI service domains by category, the
// sanctioned (allowed) destinations, and ECH public names.

#include "common.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Lowercase, strip trailing dots and a leading "*." wildcard.
std::string normalize_host(std::string s);

class Indicators {
public:
    Indicators();

    // Loads and validates the YAML file. On failure returns false and sets err.
    bool load(const std::string& path, std::string& err);

    // Programmatic population (tests / fuzzing).
    void add_category_domain(const std::string& category, const std::string& domain);
    bool add_sanctioned(const std::string& entry);    // domain, IP, or CIDR
    void add_ech_outer(const std::string& domain);

    // Category of the most specific listed domain equal to `host` or a parent
    // of it ("api.chatgpt.com" matches "chatgpt.com"), or nullptr.
    const std::string* category_of(const std::string& host) const;
    bool sanctioned_name(const std::string& host) const;
    bool sanctioned_ip(const IpAddr& ip) const;
    // SNI values that are only an ECH "public name" (the real name is encrypted).
    bool is_ech_outer(const std::string& sni) const;

    size_t domain_count() const { return domain_category_.size(); }
    size_t sanctioned_count() const { return sanctioned_domains_.size() + sanctioned_nets_.size(); }
    size_t category_count() const { return categories_.size(); }

private:
    struct Cidr { IpAddr net; int prefix; };
    static bool parse_cidr(const std::string& s, Cidr& out);

    std::unordered_map<std::string, std::string> domain_category_;
    std::unordered_set<std::string> categories_;
    std::unordered_set<std::string> sanctioned_domains_;
    std::vector<Cidr> sanctioned_nets_;
    std::unordered_set<std::string> ech_outer_;
};
