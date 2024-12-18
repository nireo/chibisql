#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace table {

enum class type : uint8_t {
    undefined,
    bytes,
    int64,
};

struct value {
    type ty;
    std::variant<std::string, int64_t> val;
};

struct record {
    std::vector<std::string> columns;
    std::vector<value> values;

    void add_str(const std::string &col, const std::string &str) {
        columns.push_back(col);
        values.push_back(value{type::bytes, str});
    }

    void add_int(const std::string &col, const int64_t num) {
        columns.push_back(col);
        values.push_back(value{type::int64, num});
    }

    std::optional<value> get(const std::string &col) const {
        for (size_t i = 0; i < col.size(); ++i) {
            if (col == columns[i]) {
                return values[i];
            }
        }
        return std::nullopt;
    }
};

struct table_def {
    std::string name;
    std::vector<type> types;
    std::vector<std::string> columns;
    int64_t pkeys;
    uint32_t prefix;
};

static const table_def default_table{
    .name = "@table",
    .types = {type::bytes, type::bytes},
    .columns = {"name", "def"},
    .pkeys = 1,
    .prefix = 2,
};

static const table_def meta_table{.name = "@meta",
                                  .types = {type::bytes, type::bytes},
                                  .columns = {"key", "val"},
                                  .pkeys = 1,
                                  .prefix = 1};
} // namespace table
