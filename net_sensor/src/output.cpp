#include "output.h"

#include <cctype>
#include <cmath>
#include <ctime>

namespace {

void json_escape(std::string& out, const std::string& s) {
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20 || c >= 0x7f) {        // keep output pure ASCII => always valid UTF-8
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(char(c));
            }
        }
    }
}

void text_value(std::string& out, const std::string& s) {
    bool quote = s.empty();
    std::string v;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { v.push_back('\\'); v.push_back(char(c)); quote = true; }
        else if (c < 0x20 || c >= 0x7f) {
            char buf[6];
            std::snprintf(buf, sizeof buf, "\\x%02x", c);
            v += buf;
        } else {
            if (c == ' ' || c == '=') quote = true;
            v.push_back(char(c));
        }
    }
    if (quote) { out.push_back('"'); out += v; out.push_back('"'); }
    else out += v;
}

}  // namespace

std::string iso8601(Ts ts) {
    const time_t sec = time_t(ts / kSec);
    const long ms = long((ts % kSec) / kMs);
    struct tm tm{};
    gmtime_r(&sec, &tm);
    char buf[64];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    return buf;
}

Event& Event::num(const char* key, double v, int precision) {
    if (!std::isfinite(v)) v = 0;
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.*f", precision, v);
    fields_.push_back({key, buf, false});
    return *this;
}

void Output::emit(const Event& e) {
    ++emitted_;
    if (!out_) return;
    std::string line;
    line.reserve(256);
    if (fmt_ == OutputFormat::Json) {
        line += "{\"ts\":\"" + iso8601(e.ts()) + "\",\"event\":\"" + e.type() + "\"";
        for (const auto& f : e.fields()) {
            line += ",\"";
            line += f.key;
            line += "\":";
            if (f.quoted) {
                line.push_back('"');
                json_escape(line, f.value);
                line.push_back('"');
            } else {
                line += f.value;
            }
        }
        line += "}\n";
    } else {
        line += iso8601(e.ts());
        line.push_back(' ');
        for (const char* p = e.type(); *p; ++p)
            line.push_back(char(std::toupper((unsigned char)*p)));
        for (const auto& f : e.fields()) {
            line.push_back(' ');
            line += f.key;
            line.push_back('=');
            text_value(line, f.value);
        }
        line.push_back('\n');
    }
    std::fwrite(line.data(), 1, line.size(), out_);
}
