#pragma once

#include "tables.h"
#include <rocksdb/db.h>
#include <string>
#include <string_view>

namespace db {
class db {
  public:
    bool get(std::string_view table, table::record *rec) const;
    bool insert(std::string_view table, table::record rec);
    bool update(std::string_view table, table::record rec);
    bool upsert(std::string_view table, table::record rec);
    bool del(std::string_view table, table::record rec);

  private:
    std::string path_;
    std::unique_ptr<rocksdb::DB> db_;

    table::table_def get_table_def(std::string_view name) const;
    bool get_with_table_def(const table::table_def tdef,
                            table::record *rec) const;
};
} // namespace db
