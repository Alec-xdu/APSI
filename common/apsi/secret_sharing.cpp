// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <iostream>

// APSI
#include "apsi/secret_sharing.h"
#include "apsi/log.h"

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

namespace apsi {
    namespace secret_sharing {

        SecretSharing::SecretSharing(const PSIParams& params) 
            : params_(params), modulus_(params.seal_params().plain_modulus().value()), cipher_ctx_(nullptr) {
            
            // 初始化OpenSSL
            OpenSSL_add_all_algorithms();
            
            // 创建加密上下文
            cipher_ctx_ = EVP_CIPHER_CTX_new();
            if (!cipher_ctx_) {
                throw std::runtime_error("Failed to create OpenSSL cipher context");
            }

            // 初始化RNG
            rng_a_ = std::make_unique<std::mt19937_64>();
            rng_b_ = std::make_unique<std::mt19937_64>();
        }

        SecretSharing::~SecretSharing() {
            if (cipher_ctx_) {
                EVP_CIPHER_CTX_free(cipher_ctx_);
            }
            EVP_cleanup();
        }

        std::vector<uint64_t> SecretSharing::generate_seed_a() {
            // 生成用于A方的RNG种子
            std::vector<uint64_t> seed(4); // 使用4个uint64作为种子
            for (auto& s : seed) {
                s = generate_random_uint64(*rng_a_);
            }
            return seed;
        }

        std::vector<uint64_t> SecretSharing::generate_seed_b() {
            // 生成用于B方的RNG种子
            std::vector<uint64_t> seed(4); // 使用4个uint64作为种子
            for (auto& s : seed) {
                s = generate_random_uint64(*rng_b_);
            }
            return seed;
        }

        std::vector<BeaverTriple> SecretSharing::generate_triples_from_seed(const std::vector<uint64_t>& seed) {
            // 从种子初始化RNG
            std::mt19937_64 rng;
            initialize_rng(rng, seed);

            // 生成Beaver三元组 [a0, b0, c0]
            std::vector<BeaverTriple> triples;
            size_t num_triples = 1000; // 可以根据需要调整数量
            
            for (size_t i = 0; i < num_triples; ++i) {
                BeaverTriple triple;
                triple.a = generate_random_uint64(rng) % modulus_;
                triple.b = generate_random_uint64(rng) % modulus_;
                triple.c = modular_multiply(triple.a, triple.b);
                triples.push_back(triple);
            }
            
            return triples;
        }

        std::vector<BeaverPair> SecretSharing::generate_pairs_from_seed(const std::vector<uint64_t>& seed) {
            // 从种子初始化RNG
            std::mt19937_64 rng;
            initialize_rng(rng, seed);

            // 生成Beaver二元组 [a1, b1]
            std::vector<BeaverPair> pairs;
            size_t num_pairs = 1000; // 可以根据需要调整数量
            
            for (size_t i = 0; i < num_pairs; ++i) {
                BeaverPair pair;
                pair.a = generate_random_uint64(rng) % modulus_;
                pair.b = generate_random_uint64(rng) % modulus_;
                pairs.push_back(pair);
            }
            
            return pairs;
        }

        uint64_t SecretSharing::compute_c1(const BeaverTriple& triple_a, const BeaverPair& pair_b) {
            // 计算 c1 = (a0 + a1) * (b0 + b1) - c0
            uint64_t a_sum = modular_add(triple_a.a, pair_b.a);
            uint64_t b_sum = modular_add(triple_a.b, pair_b.b);
            uint64_t product = modular_multiply(a_sum, b_sum);
            return modular_subtract(product, triple_a.c);
        }

        uint64_t SecretSharing::secure_multiply(uint64_t x_share, uint64_t y_share, 
                                               const BeaverTriple& triple, uint64_t modulus) {
            // 基于Beaver三元组的秘密共享乘法
            // 假设x = x0 + x1, y = y0 + y1
            // 计算 (x - a) * (y - b) + (x - a) * b + (y - b) * a + c
            
            uint64_t x_minus_a = modular_subtract(x_share, triple.a);
            uint64_t y_minus_b = modular_subtract(y_share, triple.b);
            
            uint64_t term1 = modular_multiply(x_minus_a, y_minus_b);
            uint64_t term2 = modular_multiply(x_minus_a, triple.b);
            uint64_t term3 = modular_multiply(y_minus_b, triple.a);
            
            uint64_t result = modular_add(term1, term2);
            result = modular_add(result, term3);
            result = modular_add(result, triple.c);
            
            return result % modulus;
        }

        std::vector<uint64_t> SecretSharing::compute_polynomial_powers(
            const std::vector<uint64_t>& values, 
            uint32_t exponent,
            const std::vector<BeaverTriple>& triples) {
            
            if (exponent == 0) {
                throw std::invalid_argument("exponent cannot be zero");
            }

            std::vector<uint64_t> result(values.size(), 1);
            std::vector<uint64_t> current_values = values;
            
            size_t triple_index = 0;
            
            while (exponent) {
                if (exponent & 1) {
                    // 使用秘密共享乘法计算 result * current_values
                    for (size_t i = 0; i < result.size(); ++i) {
                        if (triple_index < triples.size()) {
                            result[i] = secure_multiply(result[i], current_values[i], 
                                                      triples[triple_index++], modulus_);
                        } else {
                            // 如果三元组不够，使用普通乘法
                            result[i] = modular_multiply(result[i], current_values[i]);
                        }
                    }
                }
                
                // 计算 current_values 的平方
                for (size_t i = 0; i < current_values.size(); ++i) {
                    if (triple_index < triples.size()) {
                        current_values[i] = secure_multiply(current_values[i], current_values[i], 
                                                          triples[triple_index++], modulus_);
                    } else {
                        current_values[i] = modular_multiply(current_values[i], current_values[i]);
                    }
                }
                
                exponent >>= 1;
            }
            
            return result;
        }

        std::unordered_map<uint32_t, std::vector<uint64_t>> SecretSharing::compute_all_powers(
            const std::vector<uint64_t>& values,
            const std::vector<uint32_t>& exponents,
            const std::vector<BeaverTriple>& triples) {
            
            std::unordered_map<uint32_t, std::vector<uint64_t>> result;
            
            for (uint32_t exponent : exponents) {
                result[exponent] = compute_polynomial_powers(values, exponent, triples);
            }
            
            return result;
        }

        uint64_t SecretSharing::generate_random_uint64(std::mt19937_64& rng) {
            return rng();
        }

        std::vector<uint64_t> SecretSharing::generate_random_values(std::mt19937_64& rng, size_t count) {
            std::vector<uint64_t> values(count);
            for (size_t i = 0; i < count; ++i) {
                values[i] = generate_random_uint64(rng);
            }
            return values;
        }

        uint64_t SecretSharing::modular_add(uint64_t a, uint64_t b) const {
            uint64_t sum = a + b;
            if (sum >= modulus_) {
                sum -= modulus_;
            }
            return sum;
        }

        uint64_t SecretSharing::modular_subtract(uint64_t a, uint64_t b) const {
            if (a >= b) {
                return a - b;
            } else {
                return modulus_ - (b - a);
            }
        }

        uint64_t SecretSharing::modular_multiply(uint64_t a, uint64_t b) const {
            // 使用OpenSSL的BN进行大数乘法
            BIGNUM* bn_a = BN_new();
            BIGNUM* bn_b = BN_new();
            BIGNUM* bn_mod = BN_new();
            BIGNUM* bn_result = BN_new();
            
            BN_set_word(bn_a, a);
            BN_set_word(bn_b, b);
            BN_set_word(bn_mod, modulus_);
            
            BN_mod_mul(bn_result, bn_a, bn_b, bn_mod, nullptr);
            
            uint64_t result = BN_get_word(bn_result);
            
            BN_free(bn_a);
            BN_free(bn_b);
            BN_free(bn_mod);
            BN_free(bn_result);
            
            return result;
        }

        void SecretSharing::initialize_rng(std::mt19937_64& rng, const std::vector<uint64_t>& seed) {
            std::seed_seq seed_seq(seed.begin(), seed.end());
            rng.seed(seed_seq);
        }

    } // namespace secret_sharing
} // namespace apsi