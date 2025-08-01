// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <random>

// APSI
#include "apsi/secret_sharing_manager.h"
#include "apsi/secret_shared_powers.h"
#include "apsi/item.h"
#include "apsi/log.h"

using namespace std;
using namespace apsi;
using namespace apsi::receiver;

/**
 * Example demonstrating the secret sharing-based PSI protocol
 * This replaces the homomorphic encryption approach with secret sharing
 */
class SecretSharingPSIExample {
private:
    uint64_t modulus_;
    size_t num_items_;
    unique_ptr<SecretSharingManager> sharing_manager_;
    
public:
    SecretSharingPSIExample(uint64_t modulus, size_t num_items) 
        : modulus_(modulus), num_items_(num_items) {
        
        // Estimate number of Beaver triples needed
        size_t estimated_triples = num_items * 10; // Conservative estimate
        sharing_manager_ = make_unique<SecretSharingManager>(modulus_, estimated_triples);
        
        cout << "Initialized Secret Sharing PSI with modulus: " << modulus_ 
             << ", items: " << num_items_ << endl;
    }
    
    /**
     * Simulate the TEE (Trusted Execution Environment) seed distribution phase
     */
    void tee_seed_distribution(vector<uint8_t>& seed_a, vector<uint8_t>& seed_b) {
        cout << "\n=== TEE Seed Distribution Phase ===" << endl;
        
        sharing_manager_->distribute_seeds(seed_a, seed_b);
        
        cout << "TEE distributed seeds to party A and party B" << endl;
        cout << "Seed A length: " << seed_a.size() << " bytes" << endl;
        cout << "Seed B length: " << seed_b.size() << " bytes" << endl;
    }
    
    /**
     * Simulate party A's operations (receiver side)
     */
    void party_a_operations(const vector<uint8_t>& seed_a, 
                           const vector<Item>& items_a,
                           vector<BeaverTriple>& triples) {
        cout << "\n=== Party A Operations ===" << endl;
        
        // Convert items to field elements
        vector<uint64_t> field_elements_a;
        for (const auto& item : items_a) {
            auto words = item.get_as<uint64_t>();
            field_elements_a.push_back(words[0] % modulus_);
        }
        
        cout << "Party A has " << items_a.size() << " items" << endl;
        cout << "Converted to field elements: ";
        for (size_t i = 0; i < min(field_elements_a.size(), size_t(5)); ++i) {
            cout << field_elements_a[i] << " ";
        }
        if (field_elements_a.size() > 5) cout << "...";
        cout << endl;
        
        // Generate dummy seed for party B (in real protocol, this comes from TEE)
        vector<uint8_t> seed_b(32);
        iota(seed_b.begin(), seed_b.end(), 1); // Dummy seed
        
        // Generate Beaver triples using both seeds
        sharing_manager_->generate_beaver_triples(seed_a, seed_b, triples);
        
        cout << "Generated " << triples.size() << " Beaver triples" << endl;
        
        // Verify first triple (for demonstration)
        if (!triples.empty()) {
            const auto& triple = triples[0];
            uint64_t a_total = (triple.a0 + triple.a1) % modulus_;
            uint64_t b_total = (triple.b0 + triple.b1) % modulus_;
            uint64_t c_total = (triple.c0 + triple.c1) % modulus_;
            uint64_t expected_c = (a_total * b_total) % modulus_;
            
            cout << "First Beaver triple verification: ";
            cout << "a=" << a_total << ", b=" << b_total 
                 << ", c=" << c_total << ", expected_c=" << expected_c;
            cout << (c_total == expected_c ? " ✓" : " ✗") << endl;
        }
    }
    
    /**
     * Simulate party B's operations (sender side)
     */
    void party_b_operations(const vector<uint8_t>& seed_b, 
                           const vector<Item>& items_b) {
        cout << "\n=== Party B Operations ===" << endl;
        
        // Convert items to field elements
        vector<uint64_t> field_elements_b;
        for (const auto& item : items_b) {
            auto words = item.get_as<uint64_t>();
            field_elements_b.push_back(words[0] % modulus_);
        }
        
        cout << "Party B has " << items_b.size() << " items" << endl;
        cout << "Converted to field elements: ";
        for (size_t i = 0; i < min(field_elements_b.size(), size_t(5)); ++i) {
            cout << field_elements_b[i] << " ";
        }
        if (field_elements_b.size() > 5) cout << "...";
        cout << endl;
        
        // In real protocol, party B would also generate its shares using seed_b
        cout << "Party B generates its polynomial shares using seed B" << endl;
    }
    
    /**
     * Demonstrate polynomial computation using secret sharing
     */
    void demonstrate_polynomial_computation(const vector<BeaverTriple>& triples) {
        cout << "\n=== Polynomial Computation with Secret Sharing ===" << endl;
        
        // Sample values for polynomial computation
        vector<uint64_t> values = {2, 3, 5, 7, 11};
        vector<uint32_t> powers = {1, 2, 3};
        
        cout << "Computing polynomial powers for values: ";
        for (auto val : values) cout << val << " ";
        cout << endl;
        cout << "Powers to compute: ";
        for (auto power : powers) cout << power << " ";
        cout << endl;
        
        // Compute polynomial shares
        vector<pair<uint64_t, uint64_t>> polynomial_shares;
        sharing_manager_->compute_polynomial_powers(values, powers, polynomial_shares);
        
        cout << "Generated " << polynomial_shares.size() << " polynomial coefficient shares" << endl;
        
        // Extract and combine shares
        vector<uint64_t> shares_a, shares_b;
        for (const auto& share_pair : polynomial_shares) {
            shares_a.push_back(share_pair.first);
            shares_b.push_back(share_pair.second);
        }
        
        vector<uint64_t> combined_result;
        sharing_manager_->combine_polynomial_shares(shares_a, shares_b, combined_result);
        
        cout << "Combined polynomial results: ";
        for (size_t i = 0; i < min(combined_result.size(), size_t(10)); ++i) {
            cout << combined_result[i] << " ";
        }
        if (combined_result.size() > 10) cout << "...";
        cout << endl;
        
        // Verify some results
        size_t idx = 0;
        cout << "\nVerification (first few results):" << endl;
        for (size_t val_idx = 0; val_idx < min(values.size(), size_t(3)); ++val_idx) {
            for (uint32_t power : powers) {
                uint64_t expected = 1;
                uint64_t base = values[val_idx];
                for (uint32_t p = 0; p < power; ++p) {
                    expected = (expected * base) % modulus_;
                }
                
                cout << values[val_idx] << "^" << power << " = " 
                     << combined_result[idx] << " (expected: " << expected << ")";
                cout << (combined_result[idx] == expected ? " ✓" : " ✗") << endl;
                idx++;
            }
        }
    }
    
    /**
     * Demonstrate the complete PSI protocol simulation
     */
    void run_complete_protocol() {
        cout << "\n========== Secret Sharing PSI Protocol Demo ==========" << endl;
        
        auto start_time = chrono::high_resolution_clock::now();
        
        // Generate sample data
        vector<Item> items_a, items_b;
        generate_sample_items(items_a, items_b);
        
        // Phase 1: TEE seed distribution
        vector<uint8_t> seed_a, seed_b;
        tee_seed_distribution(seed_a, seed_b);
        
        // Phase 2: Party A operations
        vector<BeaverTriple> triples;
        party_a_operations(seed_a, items_a, triples);
        
        // Phase 3: Party B operations
        party_b_operations(seed_b, items_b);
        
        // Phase 4: Polynomial computation demonstration
        demonstrate_polynomial_computation(triples);
        
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        
        cout << "\n=== Protocol Summary ===" << endl;
        cout << "Total execution time: " << duration.count() << " ms" << endl;
        cout << "Items processed: " << items_a.size() + items_b.size() << endl;
        cout << "Beaver triples generated: " << triples.size() << endl;
        cout << "Protocol completed successfully!" << endl;
    }
    
private:
    void generate_sample_items(vector<Item>& items_a, vector<Item>& items_b) {
        cout << "\n=== Generating Sample Items ===" << endl;
        
        // Generate items for party A
        for (size_t i = 0; i < num_items_; ++i) {
            string item_str = "item_a_" + to_string(i);
            items_a.emplace_back(item_str);
        }
        
        // Generate items for party B (with some overlap)
        for (size_t i = 0; i < num_items_; ++i) {
            string item_str;
            if (i < num_items_ / 3) {
                // Create some overlapping items
                item_str = "item_a_" + to_string(i);
            } else {
                item_str = "item_b_" + to_string(i);
            }
            items_b.emplace_back(item_str);
        }
        
        cout << "Generated " << items_a.size() << " items for party A" << endl;
        cout << "Generated " << items_b.size() << " items for party B" << endl;
        cout << "Expected intersection size: " << num_items_ / 3 << endl;
    }
};

int main() {
    try {
        // Initialize logging
        Log::SetLogLevel(Log::Level::info);
        
        cout << "Secret Sharing PSI Protocol Example" << endl;
        cout << "====================================" << endl;
        
        // Protocol parameters
        uint64_t modulus = 65537; // Prime modulus for field operations
        size_t num_items = 20;    // Number of items per party
        
        // Create and run the example
        SecretSharingPSIExample example(modulus, num_items);
        example.run_complete_protocol();
        
        cout << "\nExample completed successfully!" << endl;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}