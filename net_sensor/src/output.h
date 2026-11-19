#pragma once
// Structured event output: human-readable key=value lines or JSON lines.

#include "common.h"

#include <cstdio>
#include <string>
#include <vector>

enum class OutputFormat { Text, Json };

class Event {
public:
    Event(const char* type, Ts ts) : type_(type), ts_(ts) {}

    Event& str(const char* key, const std::string& v) { fields_.push_back({key, v, true}); return *this; }
    Event& num(const char* key, double v, int precision = 3);
    Event& integer(const char* key, long long v) { fields_.push_back({key, std::to_string(v), false}); return *this; }
    Event& uinteger(const char* key, unsigned long long v) { fields_.push_back({key, std::to_string(v), false}); return *this; }
    Event& boolean(const char* key, bool v) { fields_.push_back({key, v ? "true" : "false", false}); return *this; }

    struct Field { const char* key; std::string value; bool quoted; };
    const char* type() const { return type_; }
    Ts ts() const { return ts_; }
    const std::vector<Field>& fields() const { return fields_; }

private:
    const char* type_;
    Ts ts_;
    std::vector<Field> fields_;
};

class Output {
public:
    // out == nullptr discards everything (fuzzing / benchmarks).
    explicit Output(OutputFormat fmt, FILE* out = stdout) : fmt_(fmt), out_(out) {}
    void emit(const Event& e);
    uint64_t emitted() const { return emitted_; }

private:
    OutputFormat fmt_;
    FILE* out_;
    uint64_t emitted_ = 0;
};

std::string iso8601(Ts ts);   // 2026-10-15T14:10:00.123Z
