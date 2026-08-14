#include "tx/geo/trie.h"
#include "tx/geo/aho_corasick.h"
#include "tx/geo/geosite.h"
#include "tx/common/log.h"

#include <cstdio>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

static void append_varint(std::vector<uint8_t>& out, uint64_t value) {
    while (value >= 0x80) {
        out.push_back(static_cast<uint8_t>(value | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

static void append_string_field(std::vector<uint8_t>& out, uint32_t field,
                                const std::string& value) {
    append_varint(out, (field << 3) | 2);
    append_varint(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

static void append_varint_field(std::vector<uint8_t>& out, uint32_t field,
                                uint64_t value) {
    append_varint(out, (field << 3) | 0);
    append_varint(out, value);
}

static void append_message_field(std::vector<uint8_t>& out, uint32_t field,
                                 const std::vector<uint8_t>& message) {
    append_varint(out, (field << 3) | 2);
    append_varint(out, message.size());
    out.insert(out.end(), message.begin(), message.end());
}

static std::vector<uint8_t> make_domain(uint32_t type, const std::string& value) {
    std::vector<uint8_t> domain;
    append_varint_field(domain, 1, type);
    append_string_field(domain, 2, value);
    return domain;
}

static std::vector<uint8_t> make_geosite_dat() {
    std::vector<uint8_t> site;
    append_string_field(site, 1, "CN");
    append_message_field(site, 2, make_domain(0, "google"));
    append_message_field(site, 2, make_domain(2, "bilibili.com"));
    append_message_field(site, 2, make_domain(3, "full.example"));
    append_message_field(site, 2, make_domain(1, "^regex[0-9]+\\.example$"));

    std::vector<uint8_t> list;
    append_message_field(list, 1, site);
    return list;
}

static void test_reverse_trie_suffix() {
    printf("  test_reverse_trie_suffix... ");
    tx::ReverseTrie trie;

    trie.insert_domain("google.com", "cn");
    trie.insert_domain("baidu.com", "cn");
    trie.insert_domain("github.com", "global");

    // Suffix match
    assert(trie.match("www.google.com", "cn"));
    assert(trie.match("mail.google.com", "cn"));
    assert(trie.match("google.com", "cn"));
    assert(trie.match("baidu.com", "cn"));

    // Non-match
    assert(!trie.match("example.com", "cn"));
    assert(!trie.match("google.com", "us"));

    // Different country
    assert(trie.match("github.com", "global"));
    assert(!trie.match("github.com", "cn"));

    printf("OK\n");
}

static void test_reverse_trie_deep() {
    printf("  test_reverse_trie_deep... ");
    tx::ReverseTrie trie;

    trie.insert_domain("a.b.c.example.com", "test");

    assert(trie.match("x.a.b.c.example.com", "test"));
    assert(trie.match("a.b.c.example.com", "test"));
    assert(!trie.match("b.c.example.com", "test"));

    printf("OK\n");
}

static void test_reverse_trie_label_boundary() {
    printf("  test_reverse_trie_label_boundary... ");
    tx::ReverseTrie trie;

    trie.insert_domain("google.com", "global");

    assert(trie.match("google.com", "global"));
    assert(trie.match("www.google.com", "global"));
    assert(!trie.match("www.google.com.cn", "global"));
    assert(!trie.match("notgoogle.com", "global"));
    assert(!trie.match("evilgoogle.com", "global"));
    assert(trie.lookup("notgoogle.com").empty());

    printf("OK\n");
}

static void test_aho_corasick_basic() {
    printf("  test_aho_corasick_basic... ");
    tx::AhoCorasick ac;

    ac.add_pattern("hello", "greeting");
    ac.add_pattern("world", "greeting");
    ac.add_pattern("test", "testing");
    ac.build();

    assert(ac.search("say hello to the world", "greeting"));
    assert(ac.search("this is a test", "testing"));
    assert(!ac.search("nothing here", "greeting"));
    assert(!ac.search("nothing here", "testing"));

    printf("OK\n");
}

static void test_aho_corasick_overlapping() {
    printf("  test_aho_corasick_overlapping... ");
    tx::AhoCorasick ac;

    ac.add_pattern("abc", "t1");
    ac.add_pattern("bcd", "t2");
    ac.add_pattern("abcde", "t3");
    ac.build();

    assert(ac.search("abcde", "t1"));
    assert(ac.search("abcde", "t2"));
    assert(ac.search("abcde", "t3"));
    assert(!ac.search("xyz", "t1"));

    tx::AhoCorasick suffixes;
    suffixes.add_pattern("ab", "first");
    suffixes.add_pattern("b", "second");
    suffixes.add_pattern("doubleclick", "ads");
    suffixes.add_pattern("click", "suffix");
    suffixes.build();
    assert(suffixes.search("ab", "first"));
    assert(suffixes.search("ab", "second"));
    assert(suffixes.search("doubleclick", "ads"));
    assert(suffixes.search("doubleclick", "suffix"));
    const auto matches = suffixes.search_all("ab doubleclick");
    assert(matches.size() == 4);

    printf("OK\n");
}

static void test_aho_corasick_empty() {
    printf("  test_aho_corasick_empty... ");
    tx::AhoCorasick ac;
    ac.build();
    assert(!ac.search("anything", "test"));
    printf("OK\n");
}

static void test_geosite_domain_match_excludes_plain_rules() {
    printf("  test_geosite_domain_match_excludes_plain_rules... ");

    const std::string path = "/tmp/tx_test_geosite_match_domain.dat";
    auto data = make_geosite_dat();
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }

    tx::GeoSiteMatcher matcher;
    assert(matcher.load(path));

    assert(matcher.match("www.google.com", "cn"));
    assert(!matcher.match_domain("www.google.com", "cn"));
    assert(matcher.match_domain("www.bilibili.com", "cn"));
    assert(matcher.match_domain("WWW.BILIBILI.COM", "CN"));
    assert(!matcher.match_domain("notbilibili.com", "cn"));
    assert(matcher.match("full.example", "cn"));
    assert(!matcher.match("www.full.example", "cn"));
    assert(matcher.match("regex42.example", "cn"));
    assert(!matcher.match("regex.example", "cn"));
    assert(matcher.has_tag("CN"));

    std::remove(path.c_str());

    printf("OK\n");
}

static void test_malformed_geosite_is_rejected() {
    const auto rejected = [](const char* name, const std::vector<uint8_t>& data) {
        const std::string path = std::string("/tmp/tx_test_geosite_") + name + ".dat";
        {
            std::ofstream out(path, std::ios::binary);
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        tx::GeoSiteMatcher matcher;
        assert(!matcher.load(path));
        std::remove(path.c_str());
    };

    std::vector<uint8_t> empty_site;
    append_string_field(empty_site, 1, "EMPTY");
    append_message_field(empty_site, 2, make_domain(2, ""));
    std::vector<uint8_t> empty_list;
    append_message_field(empty_list, 1, empty_site);
    rejected("empty", empty_list);

    std::vector<uint8_t> regex_site;
    append_string_field(regex_site, 1, "REGEX");
    append_message_field(regex_site, 2, make_domain(1, "[unterminated"));
    std::vector<uint8_t> regex_list;
    append_message_field(regex_list, 1, regex_site);
    rejected("regex", regex_list);

    rejected("long_length", {0x0a, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff, 0xff, 0xff, 0xff, 0x01});
    rejected("long_varint", {0x80, 0x80, 0x80, 0x80, 0x80,
                              0x80, 0x80, 0x80, 0x80, 0x02});
    rejected("truncated_fixed", {0x09, 0x01, 0x02, 0x03});
}

int main() {
    printf("=== GeoSite Tests ===\n");
    test_reverse_trie_suffix();
    test_reverse_trie_deep();
    test_reverse_trie_label_boundary();
    test_aho_corasick_basic();
    test_aho_corasick_overlapping();
    test_aho_corasick_empty();
    test_geosite_domain_match_excludes_plain_rules();
    test_malformed_geosite_is_rejected();
    printf("All GeoSite tests passed!\n");
    return 0;
}
