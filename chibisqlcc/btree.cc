#include "btree.h"
#include <cassert>
#include <cstdint>
#include <cstring>

namespace btree {

btree::btree(get_node_fn get_fn, create_node_fn create_fn,
             del_node_fn delete_fn)
    : root_(0), get_(std::move(get_fn)), create_(std::move(create_fn)),
      delete_(std::move(delete_fn)) {}

// Node format:
// | type | nkeys |  pointers  |   offsets  | key-values
// |  2B  |   2B  | nkeys * 8B | nkeys * 2B | ...

// Key-value format:
// | klen | vlen | key | val |
// |  2B  |  2B  | ... | ... |

node::node(node_type type) : data_(PAGE_SIZE, 0) { set_header(type, 0); }

node &node::operator=(const node &other) {
    if (this != &other) {
        data_ = other.data_;
    }
    return *this;
}
node_type node::get_type() const {
    uint16_t type;
    std::memcpy(&type, data_.data(), sizeof(uint16_t));
    return static_cast<node_type>(type);
}

uint16_t node::nbytes() const { return get_kv_pos(nkeys()); }

uint16_t node::nkeys() const {
    uint16_t numKeys;
    std::memcpy(&numKeys, data_.data() + 2, sizeof(uint16_t));
    return numKeys;
}

void node::set_header(node_type type, uint16_t numKeys) {
    uint16_t typeVal = static_cast<uint16_t>(type);
    std::memcpy(data_.data(), &typeVal, sizeof(uint16_t));
    std::memcpy(data_.data() + 2, &numKeys, sizeof(uint16_t));
}

uint64_t node::get_ptr(uint16_t idx) const {
    assert(idx < nkeys());
    uint64_t ptr;
    std::memcpy(&ptr, data_.data() + HEADER + 8 * idx, sizeof(uint64_t));
    return ptr;
}

void node::set_ptr(uint16_t idx, uint64_t val) {
    assert(idx < nkeys());
    std::memcpy(data_.data() + HEADER + 8 * idx, &val, sizeof(uint64_t));
}

uint16_t node::get_offset_pos(uint16_t idx) const {
    assert(1 <= idx && idx <= nkeys());
    return static_cast<uint16_t>(HEADER + (8 * nkeys()) + (2 * (idx - 1)));
}

uint16_t node::get_offset(uint16_t idx) const {
    if (idx == 0)
        return 0;
    uint16_t offset;
    std::memcpy(&offset, data_.data() + get_offset_pos(idx), sizeof(uint16_t));
    return offset;
}

void node::set_offset(uint16_t idx, uint16_t offset) {
    std::memcpy(data_.data() + get_offset_pos(idx), &offset, sizeof(uint16_t));
}

uint16_t node::get_kv_pos(uint16_t idx) const {
    assert(idx <= nkeys());
    return HEADER + 8 * nkeys() + 2 * nkeys() + get_offset(idx);
}

std::pair<std::string_view, std::string_view> node::get_kv(uint16_t idx) const {
    assert(idx < nkeys());
    uint16_t pos = get_kv_pos(idx);
    uint16_t key_len, val_len;

    std::memcpy(&key_len, data_.data() + pos, sizeof(uint16_t));
    std::memcpy(&val_len, data_.data() + pos + 2, sizeof(uint16_t));

    const char *key_start =
        reinterpret_cast<const char *>(data_.data() + pos + 4);
    const char *val_start = key_start + key_len;

    return {std::string_view(key_start, key_len),
            std::string_view(val_start, val_len)};
}

void node::append_kv(uint16_t idx, uint64_t ptr, std::string_view key,
                     std::string_view value) {
    set_ptr(idx, ptr);

    auto pos = get_kv_pos(idx);
    auto klen = static_cast<uint16_t>(key.length());
    auto vlen = static_cast<uint16_t>(value.length());

    assert(pos + 4 + klen + vlen <= PAGE_SIZE);

    std::memcpy(data_.data() + pos, &klen, sizeof(uint16_t));
    std::memcpy(data_.data() + pos + 2, &vlen, sizeof(uint16_t));
    std::memcpy(data_.data() + pos + 4, key.data(), klen);
    std::memcpy(data_.data() + pos + 4 + klen, value.data(), vlen);

    set_offset(idx + 1, get_offset(idx) + 4 + klen + vlen);
}

void node::leaf_delete(const node &old, uint16_t idx) {
    set_header(node_type::leaf, old.nkeys() - 1);
    append_range(old, 0, 0, idx);
    append_range(old, idx, idx + 1, old.nkeys() - (idx + 1));
}

void node::leaf_insert(const node &old, uint16_t idx, std::string_view key,
                       std::string_view value) {
    set_header(node_type::leaf, old.nkeys() + 1);
    append_range(old, 0, 0, idx);
    append_kv(idx, 0, key, value);
    append_range(old, idx + 1, idx, old.nkeys() - idx);
}

void node::leaf_update(const node &old, uint16_t idx, std::string_view key,
                       std::string_view value) {
    set_header(node_type::leaf, old.nkeys());
    append_range(old, 0, 0, idx);
    append_kv(idx, 0, key, value);
    append_range(old, idx + 1, idx + 1, old.nkeys() - (idx + 1));
}

static int compare_keys(std::string_view key1, std::string_view key2) {
    size_t min_len = std::min(key1.length(), key2.length());
    int cmp = std::memcmp(key1.data(), key2.data(), min_len);
    if (cmp != 0)
        return cmp;
    return static_cast<int>(key1.length()) - static_cast<int>(key2.length());
}

uint16_t node::find_key_idx(std::string_view key) const {
    uint16_t num_keys = nkeys();
    uint16_t found = 0;

    for (uint16_t i = 1; i < num_keys; i++) {
        auto [curr_key, _] = get_kv(i);
        int cmp = compare_keys(curr_key, key);
        if (cmp <= 0) {
            found = i;
        }
        if (cmp >= 0) {
            break;
        }
    }
    return found;
}

void node::node_replace_kid(uint16_t idx, uint64_t ptr) {
    assert(idx < nkeys());
    set_ptr(idx, ptr);
}

int btree::should_merge(const node &parent, uint16_t idx, const node &updated,
                        node_ptr &sibling) {
    if (updated.nbytes() > PAGE_SIZE / 4) {
        return 0; // No need to merge
    }

    // Try merging with left sibling
    if (idx > 0) {
        sibling = get_(parent.get_ptr(idx - 1));
        uint16_t merged_size = sibling->nbytes() + updated.nbytes() - HEADER;
        if (merged_size <= PAGE_SIZE) {
            return -1; // Merge with left
        }
    }

    // Try merging with right sibling
    if (idx + 1 < parent.nkeys()) {
        sibling = get_(parent.get_ptr(idx + 1));
        uint16_t merged_size = sibling->nbytes() + updated.nbytes() - HEADER;
        if (merged_size <= PAGE_SIZE) {
            return 1; // Merge with right
        }
    }

    return 0; // No merge possible
}

void node::set_kv(uint16_t idx, std::string_view key, std::string_view value) {
    uint16_t pos = get_kv_pos(idx);
    uint16_t klen = static_cast<uint16_t>(key.length());
    uint16_t vlen = static_cast<uint16_t>(value.length());

    std::memcpy(data_.data() + pos, &klen, sizeof(uint16_t));
    std::memcpy(data_.data() + pos + 2, &vlen, sizeof(uint16_t));
    std::memcpy(data_.data() + pos + 4, key.data(), klen);
    std::memcpy(data_.data() + pos + 4 + klen, value.data(), vlen);

    set_offset(idx + 1, get_offset(idx) + 4 + klen + vlen);
}

static void split_node2(node &left, node &right, const node &old) {
    uint16_t nkeys = old.nkeys();
    assert(nkeys >= 2);

    uint16_t nleft = nkeys / 2;

    // First determine the split point based on space
    while (true) {
        uint16_t left_bytes =
            HEADER + 8 * nleft + 2 * nleft + old.get_offset(nleft);
        if (left_bytes <= PAGE_SIZE || nleft <= 1) {
            break;
        }
        nleft--;
    }
    assert(nleft >= 1);

    // Adjust split point if right node would be too large
    while (true) {
        uint16_t total_bytes = old.nbytes();
        uint16_t left_bytes =
            HEADER + 8 * nleft + 2 * nleft + old.get_offset(nleft);
        uint16_t right_bytes = total_bytes - left_bytes + HEADER;
        if (right_bytes <= PAGE_SIZE || nleft >= nkeys - 1) {
            break;
        }
        nleft++;
    }

    assert(nleft < nkeys);
    uint16_t nright = nkeys - nleft;

    auto btype = old.get_type();
    left.set_header(btype, nleft);
    right.set_header(btype, nright);

    // Copy left part
    left.append_range(old, 0, 0, nleft);

    // Copy right part
    right.append_range(old, 0, nleft, nright);

    // Verify sizes
    assert(right.nbytes() <= PAGE_SIZE);
}

std::vector<node_ptr> btree::split_node(const node_ptr &old_node) {
    std::vector<node_ptr> result;
    result.reserve(3);

    if (old_node->nbytes() <= PAGE_SIZE) {
        result.push_back(std::make_unique<node>(*old_node));
        return result;
    }

    auto left = std::make_unique<node>(old_node->get_type(), PAGE_SIZE * 2);
    auto right = std::make_unique<node>(old_node->get_type(), PAGE_SIZE);

    split_node2(*left, *right, *old_node);

    if (left->nbytes() <= PAGE_SIZE) {
        // If left node fits in a single page
        left->data_.resize(PAGE_SIZE);
        result.push_back(std::move(left));
        result.push_back(std::move(right));
    } else {
        // If left node needs to be split again
        auto leftleft = std::make_unique<node>(old_node->get_type(), PAGE_SIZE);
        auto middle = std::make_unique<node>(old_node->get_type(), PAGE_SIZE);

        split_node2(*leftleft, *middle, *left);

        assert(leftleft->nbytes() <= PAGE_SIZE);
        result.push_back(std::move(leftleft));
        result.push_back(std::move(middle));
        result.push_back(std::move(right));
    }
    return result;
}

node_ptr btree::merge_nodes(const node_ptr &left, const node_ptr &right) const {
    auto result = std::make_unique<node>();
    result->set_header(left->get_type(), left->nkeys() + right->nkeys());
    result->append_range(*left, 0, 0, left->nkeys());
    result->append_range(*right, left->nkeys(), 0, right->nkeys());
    assert(result->nbytes() <= PAGE_SIZE);
    return result;
}

std::optional<std::string> btree::find(std::string_view key) const {
    if (root_ == 0) {
        return std::nullopt;
    }

    auto current = get_(root_);
    while (true) {
        uint16_t idx = current->find_key_idx(key);
        if (current->get_type() == node_type::leaf) {
            auto [existing_key, value] = current->get_kv(idx);
            if (key == existing_key) {
                return std::string(value);
            }
            return std::nullopt;
        }
        current = get_(current->get_ptr(idx));
    }
}

node_ptr btree::insert_internal(const node_ptr &n, std::string_view key,
                                std::string_view value) {
    auto new_node = std::make_unique<node>(n->get_type(), PAGE_SIZE * 2);
    uint16_t idx = n->find_key_idx(key);

    if (n->get_type() == node_type::leaf) {
        auto [existing_key, _] = n->get_kv(idx);
        if (key == existing_key) {
            new_node->leaf_update(*n, idx, key, value);
        } else {
            new_node->leaf_insert(*n, idx + 1, key, value);
        }
    } else {
        uint64_t kid_ptr = n->get_ptr(idx);
        auto kid_node = insert_internal(get_(kid_ptr), key, value);
        auto split = split_node(kid_node);
        delete_(kid_ptr);

        if (split.size() == 1 &&
            split[0]->get_kv(0).first == n->get_kv(idx).first) {
            new_node->set_header(node_type::internal, n->nkeys());
            new_node->append_range(*n, 0, 0, idx);
            new_node->append_kv(idx, create_(*split[0]),
                                split[0]->get_kv(0).first, "");
            new_node->append_range(*n, idx + 1, idx + 1,
                                   n->nkeys() - (idx + 1));
        } else {
            new_node->set_header(node_type::internal,
                                 n->nkeys() + split.size() - 1);
            new_node->append_range(*n, 0, 0, idx);
            for (size_t i = 0; i < split.size(); i++) {
                auto [first_key, _] = split[i]->get_kv(0);
                uint64_t ptr = create_(*split[i]);
                new_node->append_kv(idx + i, ptr, first_key, "");
            }
            new_node->append_range(*n, idx + split.size(), idx + 1,
                                   n->nkeys() - (idx + 1));
        }
    }
    return new_node;
}

void btree::insert(std::string_view key, std::string_view value) {
    assert(!key.empty());
    assert(key.length() <= MAX_KEY_SIZE);
    assert(value.length() <= MAX_VAL_SIZE);

    uint16_t total_size = 4 + key.length() + value.length();
    assert(total_size <= PAGE_SIZE - HEADER);

    if (root_ == 0) {
        auto root = std::make_unique<node>(node_type::leaf, PAGE_SIZE);
        root->set_header(node_type::leaf, 2);
        root->append_kv(0, 0, "", "");
        root->append_kv(1, 0, key, value);
        root_ = create_(*root);
        return;
    }

    auto n = insert_internal(get_(root_), key, value);
    auto split = split_node(n);

    if (split.size() > 1) {
        // Create new root for split nodes
        auto root = std::make_unique<node>(node_type::internal, PAGE_SIZE);
        root->set_header(node_type::internal, split.size());

        // Add all split nodes to the new root
        for (size_t i = 0; i < split.size(); i++) {
            auto [first_key, _] = split[i]->get_kv(0);
            uint64_t ptr = create_(*split[i]);
            root->append_kv(i, ptr, first_key, "");
        }

        delete_(root_); // Delete old root
        root_ = create_(*root);
    } else {
        delete_(root_); // Delete old root
        root_ = create_(*split[0]);
    }
}

void node::append_range(const node &old_node, uint16_t dst_idx,
                        uint16_t src_idx, uint16_t n) {
    assert(src_idx + n <= old_node.nkeys());
    assert(dst_idx + n <= nkeys());
    if (n == 0)
        return;

    // Copy pointers
    for (uint16_t i = 0; i < n; i++) {
        set_ptr(dst_idx + i, old_node.get_ptr(src_idx + i));
    }

    // Calculate and set offsets
    uint16_t dst_begin = get_offset(dst_idx);
    uint16_t src_begin = old_node.get_offset(src_idx);

    for (uint16_t i = 1; i <= n; ++i) {
        uint16_t offset =
            dst_begin + old_node.get_offset(src_idx + i) - src_begin;
        set_offset(dst_idx + i, offset);
    }

    // Copy key-value data
    uint16_t begin = old_node.get_kv_pos(src_idx);
    uint16_t end = old_node.get_kv_pos(src_idx + n);
    assert(begin <= end);
    assert(end <= old_node.data_.size());
    assert(get_kv_pos(dst_idx) + (end - begin) <= data_.size());

    std::memcpy(data_.data() + get_kv_pos(dst_idx),
                old_node.data_.data() + begin, end - begin);
}

node_ptr btree::remove_internal(const node_ptr &n, std::string_view key) {
    uint16_t idx = n->find_key_idx(key);

    if (n->get_type() == node_type::leaf) {
        auto [existing_key, _] = n->get_kv(idx);
        if (key != existing_key) {
            return nullptr; // Not found
        }
        auto new_node = std::make_unique<node>();
        new_node->leaf_delete(*n, idx);
        return new_node;
    }

    uint64_t kid_ptr = n->get_ptr(idx);
    auto updated = remove_internal(get_(kid_ptr), key);
    if (!updated) {
        return nullptr; // Not found
    }
    delete_(kid_ptr);

    auto new_node = std::make_unique<node>();
    node_ptr sibling;
    int merge_dir = should_merge(*n, idx, *updated, sibling);

    if (merge_dir < 0) { // Merge with left sibling
        auto merged = merge_nodes(sibling, updated);
        delete_(n->get_ptr(idx - 1));
        auto [key_val, _] = merged->get_kv(0);
        new_node->set_header(node_type::internal, n->nkeys() - 1);
        new_node->append_range(*n, 0, 0, idx - 1);
        new_node->append_kv(idx - 1, create_(*merged), key_val, "");
        new_node->append_range(*n, idx, idx + 1, n->nkeys() - (idx + 1));
    } else if (merge_dir > 0) { // Merge with right sibling
        auto merged = merge_nodes(updated, sibling);
        delete_(n->get_ptr(idx + 1));
        auto [key_val, _] = merged->get_kv(0);
        new_node->set_header(node_type::internal, n->nkeys() - 1);
        new_node->append_range(*n, 0, 0, idx);
        new_node->append_kv(idx, create_(*merged), key_val, "");
        new_node->append_range(*n, idx + 1, idx + 2, n->nkeys() - (idx + 2));
    } else if (merge_dir == 0 && updated->nkeys() == 0) {
        assert(n->nkeys() == 1 && idx == 0);
        new_node->set_header(node_type::internal, 0);
    } else { // No merge needed
        new_node->set_header(node_type::internal, n->nkeys());
        new_node->append_range(*n, 0, 0, idx);
        new_node->append_kv(idx, create_(*updated), updated->get_kv(0).first,
                            "");
        new_node->append_range(*n, idx + 1, idx + 1, n->nkeys() - (idx + 1));
    }
    return new_node;
}

bool btree::remove(std::string_view key) {
    assert(!key.empty());
    assert(key.length() <= MAX_KEY_SIZE);

    if (root_ == 0) {
        return false;
    }

    auto updated = remove_internal(get_(root_), key);
    if (!updated) {
        return false;
    }

    delete_(root_);
    if (updated->get_type() == node_type::internal && updated->nkeys() == 1) {
        root_ = updated->get_ptr(0); // Remove a level
    } else {
        root_ = create_(*updated);
    }
    return true;
}

} // namespace btree
