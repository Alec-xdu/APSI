// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <functional>

// Project
#include "../include/secret_sharing_psi_receiver.h"

// OpenSSL for hashing
#include <openssl/sha.h>

using namespace std;

namespace secret_sharing_psi {
    
    // Item implementation
    Item::Item(const string& data) {
        hash_string_to_value(data);
    }
    
    Item::Item(uint64_t value) : value_(value) {}
    
    string Item::to_string() const {
        return "Item(" + std::to_string(value_) + ")";
    }
    
    void Item::hash_string_to_value(const string& data) {
        if (data.empty()) {
            throw invalid_argument("Item data cannot be empty");
        }
        
        // Use SHA-256 to hash the string to a 64-bit value
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
        
        // Take first 8 bytes as uint64_t
        value_ = 0;
        for (int i = 0; i < 8 && i < SHA256_DIGEST_LENGTH; ++i) {
            value_ = (value_ << 8) | hash[i];
        }
    }
    
    // SecretSharingPSIReceiver implementation
    SecretSharingPSIReceiver::SecretSharingPSIReceiver(uint64_t modulus, size_t max_items)
        : modulus_(modulus), max_items_(max_items) {
        
        if (modulus == 0) {
            throw invalid_argument("modulus cannot be zero");
        }
        if (max_items == 0) {
            throw invalid_argument("max_items cannot be zero");
        }
        
        // Estimate number of Beaver triples needed
        size_t estimated_triples = max_items * 20; // Conservative estimate
        sharing_manager_ = make_unique<SecretSharingManager>(modulus_, estimated_triples);
        
        cout << "SecretSharingPSIReceiver initialized with modulus: " << modulus_ 
             << ", max_items: " << max_items_ << endl;
    }
    
    SecretSharingPSIReceiver::~SecretSharingPSIReceiver() = default;
    
    void SecretSharingPSIReceiver::set_items(const vector<Item>& items) {
        if (items.size() > max_items_) {
            throw invalid_argument("Number of items exceeds maximum allowed");
        }
        
        items_ = items;
        cout << "Set " << items_.size() << " items for PSI receiver" << endl;
    }
    
    void SecretSharingPSIReceiver::set_items(const vector<string>& item_strings) {
        if (item_strings.size() > max_items_) {
            throw invalid_argument("Number of items exceeds maximum allowed");
        }
        
        items_.clear();
        items_.reserve(item_strings.size());
        
        for (const auto& str : item_strings) {
            items_.emplace_back(str);
        }
        
        cout << "Set " << items_.size() << " string items for PSI receiver" << endl;
    }
    
    SecretSharingPSIReceiver::QueryData SecretSharingPSIReceiver::create_query(
        const vector<uint32_t>& powers) {
        
        if (items_.empty()) {
            throw runtime_error("No items set for PSI receiver");
        }
        
        QueryData query_data;
        query_data.powers = powers;
        query_data.modulus = modulus_;
        
        cout << "\n=== Creating PSI Query using Secret Sharing ===" << endl;
        
        // Step 1: TEE seed distribution
        sharing_manager_->distribute_seeds(query_data.seed_a, query_data.seed_b);
        
        // Step 2: Convert items to field elements
        vector<uint64_t> field_elements = items_to_field_elements();
        
        cout << "Converted " << field_elements.size() << " items to field elements" << endl;
        
        // Step 3: Compute polynomial powers using secret sharing
        sharing_manager_->compute_polynomial_powers(
            field_elements, powers, query_data.polynomial_shares);
        
        cout << "Generated " << query_data.polynomial_shares.size() 
             << " polynomial coefficient shares" << endl;
        
        return query_data;
    }
    
    unordered_set<Item> SecretSharingPSIReceiver::process_response(
        const vector<uint64_t>& sender_shares,
        const QueryData& query_data) {
        
        cout << "\n=== Processing Sender Response ===" << endl;
        
        // Extract receiver's shares
        vector<uint64_t> receiver_shares;
        for (const auto& share_pair : query_data.polynomial_shares) {
            receiver_shares.push_back(share_pair.first); // Take party A's share
        }
        
        if (receiver_shares.size() != sender_shares.size()) {
            throw invalid_argument("Mismatched share vector sizes");
        }
        
        // Combine shares to get final polynomial coefficients
        vector<uint64_t> polynomial_coefficients;
        sharing_manager_->combine_polynomial_shares(
            receiver_shares, sender_shares, polynomial_coefficients);
        
        cout << "Combined shares to get " << polynomial_coefficients.size() 
             << " polynomial coefficients" << endl;
        
        // Evaluate polynomial at receiver's item points to find intersections
        vector<uint64_t> field_elements = items_to_field_elements();
        vector<uint64_t> evaluations = evaluate_polynomial(polynomial_coefficients, field_elements);
        
        // Items with polynomial evaluation = 0 are in the intersection
        unordered_set<Item> intersection;
        for (size_t i = 0; i < evaluations.size() && i < items_.size(); ++i) {
            if (evaluations[i] == 0) {
                intersection.insert(items_[i]);
            }
        }
        
        cout << "Found " << intersection.size() << " items in intersection" << endl;
        
        return intersection;
    }
    
    vector<uint64_t> SecretSharingPSIReceiver::items_to_field_elements() const {
        vector<uint64_t> field_elements;
        field_elements.reserve(items_.size());
        
        for (const auto& item : items_) {
            field_elements.push_back(item.to_uint64() % modulus_);
        }
        
        return field_elements;
    }
    
    vector<uint64_t> SecretSharingPSIReceiver::evaluate_polynomial(
        const vector<uint64_t>& coefficients,
        const vector<uint64_t>& points) const {
        
        vector<uint64_t> evaluations;
        evaluations.reserve(points.size());
        
        for (uint64_t point : points) {
            uint64_t result = 0;
            uint64_t power_of_point = 1;
            
            // Evaluate polynomial using Horner's method
            for (size_t i = 0; i < coefficients.size(); ++i) {
                uint64_t term = (static_cast<__uint128_t>(coefficients[i]) * power_of_point) % modulus_;
                result = (result + term) % modulus_;
                power_of_point = (static_cast<__uint128_t>(power_of_point) * point) % modulus_;
            }
            
            evaluations.push_back(result);
        }
        
        return evaluations;
    }
    
} // namespace secret_sharing_psi