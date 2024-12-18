#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace btree {
constexpr size_t PAGE_SIZE = 4096;
constexpr size_t MAX_KEY_SIZE = 1000;
constexpr size_t HEADER = 4;
constexpr size_t MAX_VAL_SIZE = 3000;

enum class node_type : uint16_t {
    internal,
    leaf,
};

class node;
using node_ptr = std::unique_ptr<node>;
using get_node_fn = std::function<node_ptr(uint64_t)>;
using create_node_fn = std::function<uint64_t(const node &)>;
using del_node_fn = std::function<void(uint64_t)>;

class node {
  public:
    node(node_type type = node_type::leaf);

    node(node_type type, size_t size = PAGE_SIZE) : data_(size, 0) {
        set_header(type, 0);
    }
    // node(const node &other);
    node &operator=(const node &other);

    node_type get_type() const;
    uint16_t nkeys() const;
    uint16_t nbytes() const;

    void set_header(node_type type, uint16_t nkeys);
    uint64_t get_ptr(uint16_t idx) const;
    void set_ptr(uint16_t idx, uint64_t val);
    std::pair<std::string_view, std::string_view> get_kv(uint16_t idx) const;
    uint16_t find_key_idx(std::string_view key) const;
    void set_kv(uint16_t idx, std::string_view key, std::string_view value);
    void append_kv(uint16_t idx, uint64_t ptr, std::string_view key,
                   std::string_view value);
    void append_range(const node &src, uint16_t dst_start, uint16_t src_start,
                      uint16_t n);
    uint16_t get_offset_pos(uint16_t idx) const;
    uint16_t get_offset(uint16_t idx) const;
    void set_offset(uint16_t idx, uint16_t offset);
    uint16_t get_kv_pos(uint16_t idx) const;
    void leaf_insert(const node &old, uint16_t idx, std::string_view key,
                     std::string_view value);
    void leaf_update(const node &old, uint16_t idx, std::string_view key,
                     std::string_view value);
    void leaf_delete(const node &old, uint16_t idx);
    void node_replace_kid(uint16_t idx, uint64_t ptr);

    std::vector<uint8_t> data_;

  private:
};

class btree {
  public:
    btree(get_node_fn get_fn, create_node_fn create_fn, del_node_fn delete_fn);

    void insert(std::string_view key, std::string_view value);
    bool remove(std::string_view key);
    std::optional<std::string> find(std::string_view key) const;
    uint64_t root(void) const { return root_; };

  private:
    uint64_t root_;
    get_node_fn get_;
    create_node_fn create_;
    del_node_fn delete_;

    node_ptr insert_internal(const node_ptr &node, std::string_view key,
                             std::string_view value);
    node_ptr remove_internal(const node_ptr &node, std::string_view key);

    int should_merge(const node &parent, uint16_t idx, const node &updated,
                     node_ptr &sibling);

    std::vector<node_ptr> split_node(const node_ptr &node);
    node_ptr merge_nodes(const node_ptr &left, const node_ptr &right) const;
};
} // namespace btree
