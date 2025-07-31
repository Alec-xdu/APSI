// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <stdexcept>
#include <cstring>

// APSI
#include "apsi/log.h"
#include "apsi/secret_sharing_manager.h"

// OpenSSL
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

namespace apsi {
    namespace receiver {
        
        SecretSharingManager::SecretSharingManager(uint64_t modulus, size_t num_triples)
            : modulus_(modulus), num_triples_(num_triples), rng_(random_device{}())
        {
            if (modulus == 0) {
                throw invalid_argument("modulus cannot be zero");
            }
            if (num_triples == 0) {
                throw invalid_argument("num_triples cannot be zero");
            }
            
            APSI_LOG_DEBUG("SecretSharingManager initialized with modulus: " << modulus_ 
                          << ", num_triples: " << num_triples_);
        }
        
        SecretSharingManager::~SecretSharingManager() = default;
        
        void SecretSharingManager::distribute_seeds(vector<uint8_t>& seed_a, vector<uint8_t>& seed_b)
        {
            seed_a.resize(SEED_LENGTH);
            seed_b.resize(SEED_LENGTH);
            
            generate_secure_seed(seed_a);
            generate_secure_seed(seed_b);
            
            APSI_LOG_DEBUG("Seeds distributed to parties A and B");
        }
        
        void SecretSharingManager::generate_beaver_triples(
            const vector<uint8_t>& seed_a,
            const vector<uint8_t>& seed_b,
            vector<BeaverTriple>& triples)
        {
            if (seed_a.size() != SEED_LENGTH || seed_b.size() != SEED_LENGTH) {
                throw invalid_argument("Invalid seed length");
            }
            
            triples.clear();
            triples.reserve(num_triples_);
            
            // Initialize RNGs with seeds
            mt19937_64 rng_a, rng_b;
            init_rng_with_seed(seed_a, rng_a);
            init_rng_with_seed(seed_b, rng_b);
            
            for (size_t i = 0; i < num_triples_; ++i) {
                BeaverTriple triple;
                
                // Generate random shares for a and b
                triple.a0 = rng_a() % modulus_;
                triple.a1 = rng_b() % modulus_;
                triple.b0 = rng_a() % modulus_;
                triple.b1 = rng_b() % modulus_;
                
                // Compute c = (a0 + a1) * (b0 + b1) mod modulus
                uint64_t a_total = mod_add(triple.a0, triple.a1);
                uint64_t b_total = mod_add(triple.b0, triple.b1);
                uint64_t c_total = mod_mul(a_total, b_total);
                
                // Generate c0 randomly and compute c1
                triple.c0 = rng_a() % modulus_;
                triple.c1 = mod_sub(c_total, triple.c0);
                
                triples.push_back(triple);
            }
            
            APSI_LOG_DEBUG("Generated " << triples.size() << " Beaver triples");
        }
        
        void SecretSharingManager::multiply_shares(
            const pair<uint64_t, uint64_t>& x_shares,
            const pair<uint64_t, uint64_t>& y_shares,
            const BeaverTriple& triple,
            pair<uint64_t, uint64_t>& result_shares)
        {
            // Beaver triple multiplication protocol:
            // x = x0 + x1, y = y0 + y1
            // z = xy = (x0 + x1)(y0 + y1)
            // Using Beaver triple (a, b, c) where c = ab:
            // d = x - a, e = y - b
            // z = c + d*b + e*a + d*e
            
            uint64_t x0 = x_shares.first;
            uint64_t x1 = x_shares.second;
            uint64_t y0 = y_shares.first;
            uint64_t y1 = y_shares.second;
            
            // Compute d = x - a and e = y - b
            uint64_t x_total = mod_add(x0, x1);
            uint64_t y_total = mod_add(y0, y1);
            uint64_t a_total = mod_add(triple.a0, triple.a1);
            uint64_t b_total = mod_add(triple.b0, triple.b1);
            
            uint64_t d = mod_sub(x_total, a_total);
            uint64_t e = mod_sub(y_total, b_total);
            
            // Compute z0 and z1
            // z0 = c0 + d*b0 + e*a0 + (party 0 gets d*e)
            // z1 = c1 + d*b1 + e*a1
            uint64_t z0 = triple.c0;
            z0 = mod_add(z0, mod_mul(d, triple.b0));
            z0 = mod_add(z0, mod_mul(e, triple.a0));
            z0 = mod_add(z0, mod_mul(d, e));  // Only party 0 adds d*e
            
            uint64_t z1 = triple.c1;
            z1 = mod_add(z1, mod_mul(d, triple.b1));
            z1 = mod_add(z1, mod_mul(e, triple.a1));
            
            result_shares = make_pair(z0, z1);
        }
        
        void SecretSharingManager::compute_polynomial_powers(
            const vector<uint64_t>& values,
            const vector<uint32_t>& powers,
            vector<pair<uint64_t, uint64_t>>& polynomial_shares)
        {
            polynomial_shares.clear();
            polynomial_shares.reserve(values.size() * powers.size());
            
            // Generate seeds for this computation
            vector<uint8_t> seed_a, seed_b;
            distribute_seeds(seed_a, seed_b);
            
            // Generate Beaver triples for multiplication operations
            vector<BeaverTriple> triples;
            size_t required_triples = values.size() * powers.size() * 10; // Estimate
            SecretSharingManager temp_manager(modulus_, required_triples);
            temp_manager.generate_beaver_triples(seed_a, seed_b, triples);
            
            size_t triple_idx = 0;
            
            for (size_t val_idx = 0; val_idx < values.size(); ++val_idx) {
                uint64_t base_value = values[val_idx];
                
                for (uint32_t power : powers) {
                    if (power == 0) {
                        // x^0 = 1, share as (1, 0)
                        polynomial_shares.emplace_back(1, 0);
                    } else if (power == 1) {
                        // x^1 = x, share randomly
                        uint64_t share0 = rng_() % modulus_;
                        uint64_t share1 = mod_sub(base_value, share0);
                        polynomial_shares.emplace_back(share0, share1);
                    } else {
                        // Compute x^power using repeated squaring with secret sharing
                        pair<uint64_t, uint64_t> result_shares(1, 0); // Start with 1
                        pair<uint64_t, uint64_t> base_shares;
                        
                        // Share the base value
                        uint64_t base_share0 = rng_() % modulus_;
                        uint64_t base_share1 = mod_sub(base_value, base_share0);
                        base_shares = make_pair(base_share0, base_share1);
                        
                        uint32_t exp = power;
                        while (exp > 0) {
                            if (exp & 1) {
                                // Multiply result by current base
                                if (triple_idx < triples.size()) {
                                    multiply_shares(result_shares, base_shares, 
                                                  triples[triple_idx++], result_shares);
                                }
                            }
                            if (exp > 1) {
                                // Square the base
                                if (triple_idx < triples.size()) {
                                    multiply_shares(base_shares, base_shares, 
                                                  triples[triple_idx++], base_shares);
                                }
                            }
                            exp >>= 1;
                        }
                        
                        polynomial_shares.push_back(result_shares);
                    }
                }
            }
            
            APSI_LOG_DEBUG("Computed polynomial powers for " << values.size() 
                          << " values with " << powers.size() << " powers each");
        }
        
        void SecretSharingManager::combine_polynomial_shares(
            const vector<uint64_t>& shares_a,
            const vector<uint64_t>& shares_b,
            vector<uint64_t>& result)
        {
            if (shares_a.size() != shares_b.size()) {
                throw invalid_argument("Share vectors must have the same size");
            }
            
            result.clear();
            result.reserve(shares_a.size());
            
            for (size_t i = 0; i < shares_a.size(); ++i) {
                result.push_back(mod_add(shares_a[i], shares_b[i]));
            }
            
            APSI_LOG_DEBUG("Combined " << shares_a.size() << " polynomial shares");
        }
        
        void SecretSharingManager::generate_secure_seed(vector<uint8_t>& seed)
        {
            seed.resize(SEED_LENGTH);
            
            if (RAND_bytes(seed.data(), static_cast<int>(SEED_LENGTH)) != 1) {
                throw runtime_error("Failed to generate secure random seed");
            }
        }
        
        void SecretSharingManager::init_rng_with_seed(
            const vector<uint8_t>& seed, mt19937_64& rng)
        {
            if (seed.size() != SEED_LENGTH) {
                throw invalid_argument("Invalid seed length");
            }
            
            // Use SHA-256 to hash the seed into a 64-bit value for RNG initialization
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(seed.data(), seed.size(), hash);
            
            uint64_t seed_value = 0;
            memcpy(&seed_value, hash, min(sizeof(seed_value), sizeof(hash)));
            
            rng.seed(seed_value);
        }
        
        uint64_t SecretSharingManager::mod_add(uint64_t a, uint64_t b) const
        {
            // Prevent overflow in addition
            if (a >= modulus_) a %= modulus_;
            if (b >= modulus_) b %= modulus_;
            
            uint64_t result = a + b;
            if (result >= modulus_) {
                result -= modulus_;
            }
            return result;
        }
        
        uint64_t SecretSharingManager::mod_sub(uint64_t a, uint64_t b) const
        {
            if (a >= modulus_) a %= modulus_;
            if (b >= modulus_) b %= modulus_;
            
            if (a >= b) {
                return a - b;
            } else {
                return modulus_ - (b - a);
            }
        }
        
        uint64_t SecretSharingManager::mod_mul(uint64_t a, uint64_t b) const
        {
            if (a >= modulus_) a %= modulus_;
            if (b >= modulus_) b %= modulus_;
            
            // Use 128-bit arithmetic to prevent overflow
            __uint128_t result = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
            return static_cast<uint64_t>(result % modulus_);
        }
        
    } // namespace receiver
} // namespace apsi