#include "btree.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <map>
#include <queue>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

class BTreeTester {
  private:
    btree::btree tree_;
    std::map<std::string, std::string> reference_;
    std::map<uint64_t, std::vector<uint8_t>> pages_;

    std::pair<std::vector<std::string>, std::vector<std::string>> dump() {
        std::vector<std::string> keys, vals;
        if (tree_.root() == 0) {
            return {keys, vals};
        }

        // Use a queue for level-order traversal to ensure we visit all nodes
        std::queue<uint64_t> to_visit;
        std::unordered_set<uint64_t> visited;
        to_visit.push(tree_.root());

        while (!to_visit.empty()) {
            uint64_t ptr = to_visit.front();
            to_visit.pop();

            if (visited.find(ptr) != visited.end()) {
                continue;
            }
            visited.insert(ptr);

            auto node = get_node_fn(ptr);
            if (!node) {
                continue;
            }

            uint16_t nkeys = node->nkeys();

            if (node->get_type() == btree::node_type::leaf) {
                for (uint16_t i = 0; i < nkeys; i++) {
                    auto [key, val] = node->get_kv(i);
                    keys.push_back(std::string(key));
                    vals.push_back(std::string(val));
                }
            } else {
                // For internal nodes, add all child pointers to the queue
                for (uint16_t i = 0; i < nkeys; i++) {
                    uint64_t child_ptr = node->get_ptr(i);
                    if (child_ptr != 0 && child_ptr != ptr) {
                        to_visit.push(child_ptr);
                    }
                }
            }
        }

        // Remove the sentinel "" key-value pair if it exists
        if (!keys.empty() && !vals.empty() && keys[0].empty() &&
            vals[0].empty()) {
            keys.erase(keys.begin());
            vals.erase(vals.begin());
        }

        // Sort the collected keys and values to match B-tree order
        std::vector<size_t> indices(keys.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::sort(indices.begin(), indices.end(),
                  [&](size_t i, size_t j) { return keys[i] < keys[j]; });

        std::vector<std::string> sorted_keys, sorted_vals;
        sorted_keys.reserve(keys.size());
        sorted_vals.reserve(vals.size());
        for (size_t i : indices) {
            sorted_keys.push_back(keys[i]);
            sorted_vals.push_back(vals[i]);
        }

        return {sorted_keys, sorted_vals};
    }

    btree::node_ptr get_node_fn(uint64_t ptr) {
        auto it = pages_.find(ptr);
        if (it == pages_.end()) {
            return nullptr;
        }
        // Create a new node and copy the page data
        auto n = std::make_unique<btree::node>();
        n->data_ = it->second; // Use vector assignment for deep copy
        return n;
    }

    void verify_node(const btree::node_ptr &node,
                     std::unordered_set<uint64_t> &visited) {
        if (!node || node->nkeys() == 0)
            return;

        uint16_t nkeys = node->nkeys();
        assert(nkeys >= 1);

        if (node->get_type() == btree::node_type::leaf) {
            return;
        }

        for (uint16_t i = 0; i < nkeys; i++) {
            uint64_t child_ptr = node->get_ptr(i);

            if (child_ptr == 0 || visited.find(child_ptr) != visited.end()) {
                continue;
            }
            visited.insert(child_ptr);

            auto child = get_node_fn(child_ptr);
            if (!child) {
                continue;
            }

            if (child->nkeys() > 0) { // Only verify non-empty nodes
                auto [parent_key, _] = node->get_kv(i);
                auto [child_key, __] = child->get_kv(0);
                assert(parent_key == child_key);
                verify_node(child, visited);
            }
        }
    }

    void verify_tree() {
        if (tree_.root() == 0) {
            return;
        }

        auto [keys, vals] = dump();

        std::vector<std::string> ref_keys, ref_vals;
        ref_keys.reserve(reference_.size());
        ref_vals.reserve(reference_.size());

        for (const auto &pair : reference_) {
            ref_keys.push_back(pair.first);
            ref_vals.push_back(pair.second);
        }

        // Sort reference data
        std::vector<size_t> indices(ref_keys.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::sort(indices.begin(), indices.end(), [&](size_t i, size_t j) {
            return ref_keys[i] < ref_keys[j];
        });

        std::vector<std::string> sorted_ref_keys, sorted_ref_vals;
        sorted_ref_keys.reserve(ref_keys.size());
        sorted_ref_vals.reserve(ref_vals.size());

        for (size_t i : indices) {
            sorted_ref_keys.push_back(ref_keys[i]);
            sorted_ref_vals.push_back(ref_vals[i]);
        }

        // Debug output
        std::cout << "Reference size: " << sorted_ref_keys.size()
                  << ", Tree size: " << keys.size() << std::endl;

        if (sorted_ref_keys.size() != keys.size()) {
            std::cout << "First 10 reference keys: ";
            for (size_t i = 0; i < std::min(size_t(10), sorted_ref_keys.size());
                 i++) {
                std::cout << sorted_ref_keys[i] << " ";
            }
            std::cout << "\nFirst 10 tree keys: ";
            for (size_t i = 0; i < std::min(size_t(10), keys.size()); i++) {
                std::cout << keys[i] << " ";
            }
            std::cout << std::endl;
        }

        assert(sorted_ref_keys.size() == keys.size());
        assert(sorted_ref_keys == keys);
        assert(sorted_ref_vals == vals);

        // Verify node relationships
        auto root = get_node_fn(tree_.root());
        if (root) {
            std::unordered_set<uint64_t> visited;
            visited.insert(tree_.root());
            verify_node(root, visited);
        }
    }

    void verify() {
        auto [keys, vals] = dump();

        std::vector<std::string> ref_keys, ref_vals;
        for (const auto &[k, v] : reference_) {
            ref_keys.push_back(k);
            ref_vals.push_back(v);
        }

        if (ref_keys.size() != keys.size()) {
            std::cout << "Reference keys size: " << ref_keys.size()
                      << std::endl;
            std::cout << "Actual keys size: " << keys.size() << std::endl;

            std::cout << "Reference keys: ";
            for (const auto &k : ref_keys)
                std::cout << k << " ";
            std::cout << std::endl;

            std::cout << "Actual keys: ";
            for (const auto &k : keys)
                std::cout << k << " ";
            std::cout << std::endl;

            assert(ref_keys.size() == keys.size());
        }

        // Sort reference data
        std::vector<size_t> indices(ref_keys.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::sort(indices.begin(), indices.end(), [&](size_t i, size_t j) {
            return ref_keys[i] < ref_keys[j];
        });

        std::vector<std::string> sorted_keys, sorted_vals;
        for (size_t i : indices) {
            sorted_keys.push_back(ref_keys[i]);
            sorted_vals.push_back(ref_vals[i]);
        }

        assert(sorted_keys == keys);
        if (sorted_vals != vals) {
            std::cout << "Values mismatch at size: " << vals.size()
                      << std::endl;
            std::cout << "First few sorted values: ";
            for (size_t i = 0; i < std::min(size_t(5), sorted_vals.size());
                 i++) {
                std::cout << sorted_vals[i] << " ";
            }
            std::cout << std::endl;

            std::cout << "First few actual values: ";
            for (size_t i = 0; i < std::min(size_t(5), vals.size()); i++) {
                std::cout << vals[i] << " ";
            }
            std::cout << std::endl;

            // Find first mismatch
            for (size_t i = 0; i < std::min(sorted_vals.size(), vals.size());
                 i++) {
                if (sorted_vals[i] != vals[i]) {
                    std::cout << "First mismatch at index " << i << ": "
                              << "expected '" << sorted_vals[i] << "' but got '"
                              << vals[i] << "'" << std::endl;
                    break;
                }
            }
            assert(sorted_vals == vals);
        }

        // Verify node relationships
        std::function<void(const btree::node_ptr &)> verify_node =
            [&](const btree::node_ptr &node) {
                uint16_t nkeys = node->nkeys();
                assert(nkeys >= 1);

                if (node->get_type() == btree::node_type::leaf) {
                    return;
                }

                for (uint16_t i = 0; i < nkeys; i++) {
                    auto [key, _] = node->get_kv(i);
                    auto kid = get_node_fn(node->get_ptr(i));
                    auto [kid_key, __] = kid->get_kv(0);
                    assert(key == kid_key);
                    verify_node(kid);
                }
            };

        verify_node(get_node_fn(tree_.root()));
    }

  public:
    BTreeTester()
        : tree_([this](uint64_t ptr) { return get_node_fn(ptr); },
                [this](const btree::node &n) {
                    uint64_t ptr = reinterpret_cast<uint64_t>(&n);
                    assert(n.nbytes() <= btree::PAGE_SIZE);
                    pages_[ptr] = std::vector<uint8_t>(
                        n.data_); // Copy the actual node data
                    return ptr;
                },
                [this](uint64_t ptr) { pages_.erase(ptr); }) {}

    uint32_t fmix32(uint32_t h) {
        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;
        return h;
    }

    void test_basic(std::function<uint32_t(uint32_t)> hasher) {
        add("k", "v");
        verify();

        // Insert
        for (int i = 0; i < 250000; i++) {
            std::string key = "key" + std::to_string(hasher(i));
            std::string val = "vvv" + std::to_string(hasher(-i));
            add(key, val);
            if (i < 2000) {
                verify();
            }
        }
        verify();

        // Delete
        for (int i = 2000; i < 250000; i++) {
            std::string key = "key" + std::to_string(hasher(i));
            assert(del(key));
        }
        verify();

        // Overwrite
        for (int i = 0; i < 2000; i++) {
            std::string key = "key" + std::to_string(hasher(i));
            std::string val = "vvv" + std::to_string(hasher(i));
            add(key, val);
            verify();
        }

        assert(!del("kk"));

        for (int i = 0; i < 2000; i++) {
            std::string key = "key" + std::to_string(hasher(i));
            assert(del(key));
            verify();
        }

        add("k", "v2");
        verify();
        del("k");
        verify();

        // Check dummy key
        assert(pages_.size() == 1);
        assert(get_node_fn(tree_.root())->nkeys() == 1);
    }

    void test_rand_length() {
        std::random_device rd;
        std::mt19937 gen(rd());

        for (int i = 0; i < 2000; i++) {
            uint32_t klen = fmix32(2 * i) % btree::MAX_KEY_SIZE;
            uint32_t vlen = fmix32(2 * i + 1) % btree::MAX_VAL_SIZE;

            if (klen == 0)
                continue;

            std::string key(klen, 0);
            std::string val(vlen, 0);
            std::generate(key.begin(), key.end(),
                          [&]() { return static_cast<char>(gen() % 256); });

            add(key, val);
            verify();
        }
    }

    void test_inc_length() {
        std::random_device rd;
        std::mt19937 gen(rd());

        for (int l = 1; l < btree::MAX_KEY_SIZE + btree::MAX_VAL_SIZE; l++) {
            BTreeTester tester;

            int klen = std::min(l, static_cast<int>(btree::MAX_KEY_SIZE));
            int vlen = l - klen;

            std::string key(klen, 0);
            std::string val(vlen, 0);

            int factor = btree::PAGE_SIZE / l;
            int size = factor * factor * 2;
            if (size > 4000)
                size = 4000;
            if (size < 10)
                size = 10;

            for (int i = 0; i < size; i++) {
                std::generate(key.begin(), key.end(),
                              [&]() { return static_cast<char>(gen() % 256); });
                tester.add(key, val);
            }
            tester.verify();
        }
    }

    void add(const std::string &key, const std::string &val) {
        std::cout << "adding key: " << key << " val: " << val
                  << " key.length()=" << key.length()
                  << " val.length()=" << val.length() << '\n';
        tree_.insert(key, val);
        reference_[key] = val;
    }

    bool del(const std::string &key) {
        reference_.erase(key);
        return tree_.remove(key);
    }
};

int main() {
    std::cout << "running BTree tests...\n";

    try {
        BTreeTester tester;

        std::cout << "testing ascending order..." << std::endl;
        tester.test_basic([](uint32_t h) { return h; });

        std::cout << "testing descending order..." << std::endl;
        tester.test_basic([](uint32_t h) { return -h; });

        std::cout << "testing random order..." << std::endl;
        tester.test_basic([&tester](uint32_t h) { return tester.fmix32(h); });

        std::cout << "testing random lengths..." << std::endl;
        tester.test_rand_length();

        std::cout << "testing incremental lengths..." << std::endl;
        tester.test_inc_length();

        std::cout << "all tests passed!" << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "test failed: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
