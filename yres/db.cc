#include "db.h"
#include "tables.h"
#include <vector>
namespace db {
using namespace table;

static bool values_complete(const table_def &tdef, std::vector<value> values,
                            size_t n) {
    for (size_t i = 0; i < values.size(); ++i) {
        if (i < n && values[i].ty == type::undefined) {
            return false;
        } else if (i >= n && values[i].ty != type::undefined) {
            return false;
        }
    }

    return true;
}

static std::optional<std::vector<value>> reorder_record(const table_def &tdef,
                                                        const record &rec) {
    std::vector<value> res(tdef.columns.size());

    for (size_t i = 0; i < tdef.columns.size(); ++i) {
        const auto &v = rec.get(tdef.columns[i]);
        if (!v.has_value()) {
            continue;
        }

        if (v->ty != tdef.types[i]) {
            return std::nullopt;
        }
        res[i] = *v;
    }
    return res;
}

static std::optional<std::vector<value>>
check_record(const table_def &tdef, const record &rec, size_t n) {
    auto vals = reorder_record(tdef, rec);
    if (!vals.has_value()) {
        return std::nullopt;
    }

    if (!values_complete(tdef, *vals, n)) {
        return std::nullopt;
    }

    return vals;
}

bool db::get_with_table_def(const table_def &tdef, record *rec) const {
    return false;
}

} // namespace db
