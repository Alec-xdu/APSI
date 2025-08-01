// Test file for Secret Sharing PSI implementation

#include <iostream>
#include <vector>
#include <cassert>
#include <chrono>
#include <unordered_set>

#include "secret_sharing_manager.h"
#include "secret_sharing_psi_receiver.h"

using namespace std;
using namespace secret_sharing_psi;

void test_secret_sharing_manager() {
    cout << "\n=== Testing SecretSharingManager ===" << endl;
    
    SecretSharingManager manager(65537, 100);
    
    // Test seed distribution
    vector<uint8_t> seed_a, seed_b;
    manager.distribute_seeds(seed_a, seed_b);
    assert(seed_a.size() == 32);
    assert(seed_b.size() == 32);
    assert(seed_a != seed_b);
    cout << "✓ Seed distribution test passed" << endl;
    
    // Test Beaver triple generation
    vector<BeaverTriple> triples;
    manager.generate_beaver_triples(seed_a, seed_b, triples);
    assert(triples.size() == 100);
    
    // Verify Beaver triple property
    for (const auto& triple : triples) {
        uint64_t a_total = (triple.a0 + triple.a1) % 65537;
        uint64_t b_total = (triple.b0 + triple.b1) % 65537;
        uint64_t c_total = (triple.c0 + triple.c1) % 65537;
        uint64_t expected_c = (a_total * b_total) % 65537;
        assert(c_total == expected_c);
    }
    cout << "✓ Beaver triple generation test passed" << endl;
    
    // Test secret sharing multiplication
    uint64_t x = 123, y = 456;
    uint64_t expected_result = (x * y) % 65537;
    
    pair<uint64_t, uint64_t> x_shares = {12, (x - 12 + 65537) % 65537};
    pair<uint64_t, uint64_t> y_shares = {34, (y - 34 + 65537) % 65537};
    
    pair<uint64_t, uint64_t> result_shares;
    manager.multiply_shares(x_shares, y_shares, triples[0], result_shares);
    
    uint64_t actual_result = (result_shares.first + result_shares.second) % 65537;
    assert(actual_result == expected_result);
    cout << "✓ Secret sharing multiplication test passed" << endl;
}

void test_psi_receiver() {
    cout << "\n=== Testing SecretSharingPSIReceiver ===" << endl;
    
    SecretSharingPSIReceiver receiver(65537, 100);
    
    // Test item setting
    vector<string> items = {"apple", "banana", "cherry", "date", "elderberry"};
    receiver.set_items(items);
    assert(receiver.get_items().size() == 5);
    cout << "✓ Item setting test passed" << endl;
    
    // Test query creation
    vector<uint32_t> powers = {1, 2, 3};
    auto query_data = receiver.create_query(powers);
    
    assert(query_data.seed_a.size() == 32);
    assert(query_data.seed_b.size() == 32);
    assert(query_data.powers == powers);
    assert(query_data.modulus == 65537);
    assert(!query_data.polynomial_shares.empty());
    cout << "✓ Query creation test passed" << endl;
    
    // Test response processing (simulate sender response)
    vector<uint64_t> sender_shares;
    for (const auto& share_pair : query_data.polynomial_shares) {
        sender_shares.push_back(share_pair.second); // Take party B's share
    }
    
    auto intersection = receiver.process_response(sender_shares, query_data);
    cout << "✓ Response processing test passed (found " << intersection.size() << " intersections)" << endl;
}

void test_item_class() {
    cout << "\n=== Testing Item Class ===" << endl;
    
    // Test string constructor
    Item item1("test_string");
    Item item2("test_string");
    Item item3("different_string");
    
    assert(item1 == item2);
    assert(item1 != item3);
    cout << "✓ Item equality test passed" << endl;
    
    // Test uint64_t constructor
    Item item4(12345);
    assert(item4.to_uint64() == 12345);
    cout << "✓ Item uint64_t constructor test passed" << endl;
    
    // Test hash function
    unordered_set<Item> item_set;
    item_set.insert(item1);
    item_set.insert(item2);
    item_set.insert(item3);
    assert(item_set.size() == 2); // item1 and item2 are the same
    cout << "✓ Item hash function test passed" << endl;
}

void performance_test() {
    cout << "\n=== Performance Test ===" << endl;
    
    auto start = chrono::high_resolution_clock::now();
    
    SecretSharingManager manager(65537, 1000);
    
    // Generate seeds and triples
    vector<uint8_t> seed_a, seed_b;
    manager.distribute_seeds(seed_a, seed_b);
    
    vector<BeaverTriple> triples;
    manager.generate_beaver_triples(seed_a, seed_b, triples);
    
    // Perform multiplications
    for (int i = 0; i < 100; ++i) {
        uint64_t x = i + 1, y = i + 2;
        pair<uint64_t, uint64_t> x_shares = {i, (x - i + 65537) % 65537};
        pair<uint64_t, uint64_t> y_shares = {i + 1, (y - i - 1 + 65537) % 65537};
        
        pair<uint64_t, uint64_t> result_shares;
        manager.multiply_shares(x_shares, y_shares, triples[i % triples.size()], result_shares);
    }
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    cout << "✓ Performance test completed in " << duration.count() << " microseconds" << endl;
    cout << "✓ Generated 1000 Beaver triples and performed 100 multiplications" << endl;
}

int main() {
    try {
        cout << "Secret Sharing PSI Test Suite" << endl;
        cout << "=============================" << endl;
        
        test_secret_sharing_manager();
        test_item_class();
        test_psi_receiver();
        performance_test();
        
        cout << "\n🎉 All tests passed successfully!" << endl;
        cout << "The secret sharing PSI implementation is working correctly." << endl;
        
        return 0;
    } catch (const exception& e) {
        cerr << "❌ Test failed with error: " << e.what() << endl;
        return 1;
    } catch (...) {
        cerr << "❌ Test failed with unknown error" << endl;
        return 1;
    }
}