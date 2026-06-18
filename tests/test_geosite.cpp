#include "tx/geo/trie.h"
#include "tx/geo/aho_corasick.h"
#include "tx/common/log.h"

#include <cstdio>
#include <cassert>

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

    printf("OK\n");
}

static void test_aho_corasick_empty() {
    printf("  test_aho_corasick_empty... ");
    tx::AhoCorasick ac;
    ac.build();
    assert(!ac.search("anything", "test"));
    printf("OK\n");
}

int main() {
    printf("=== GeoSite Tests ===\n");
    test_reverse_trie_suffix();
    test_reverse_trie_deep();
    test_aho_corasick_basic();
    test_aho_corasick_overlapping();
    test_aho_corasick_empty();
    printf("All GeoSite tests passed!\n");
    return 0;
}
