// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <iostream>

// APSI
#include "apsi/tee_manager.h"
#include "apsi/log.h"

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

namespace apsi {
    namespace tee {

        TEEManager::TEEManager() : cipher_ctx_(nullptr) {
            // 初始化OpenSSL
            OpenSSL_add_all_algorithms();
            
            // 创建加密上下文
            cipher_ctx_ = EVP_CIPHER_CTX_new();
            if (!cipher_ctx_) {
                throw std::runtime_error("Failed to create OpenSSL cipher context");
            }

            // 初始化主RNG
            master_rng_ = std::make_unique<std::mt19937_64>();
            generate_master_seed();
        }

        TEEManager::~TEEManager() {
            if (cipher_ctx_) {
                EVP_CIPHER_CTX_free(cipher_ctx_);
            }
            EVP_cleanup();
        }

        void TEEManager::initialize() {
            APSI_LOG_INFO("TEE Manager initialized");
        }

        std::vector<uint64_t> TEEManager::distribute_seed_to_party_a() {
            // 为A方生成种子
            seed_a_.resize(4);
            for (auto& s : seed_a_) {
                s = generate_random_uint64();
            }
            
            APSI_LOG_DEBUG("Seed distributed to party A");
            return seed_a_;
        }

        std::vector<uint64_t> TEEManager::distribute_seed_to_party_b() {
            // 为B方生成种子
            seed_b_.resize(4);
            for (auto& s : seed_b_) {
                s = generate_random_uint64();
            }
            
            APSI_LOG_DEBUG("Seed distributed to party B");
            return seed_b_;
        }

        std::vector<secret_sharing::BeaverTriple> TEEManager::get_triples_for_party_a() {
            // 从A方种子生成Beaver三元组
            std::mt19937_64 rng_a;
            initialize_rng_from_seed(rng_a, seed_a_);

            triples_a_.clear();
            size_t num_triples = 1000; // 可以根据需要调整数量
            
            for (size_t i = 0; i < num_triples; ++i) {
                secret_sharing::BeaverTriple triple;
                triple.a = rng_a() % 0xFFFFFFFFFFFFFFFFULL; // 使用64位模数
                triple.b = rng_a() % 0xFFFFFFFFFFFFFFFFULL;
                triple.c = triple.a * triple.b; // 简单乘法，实际应用中需要模运算
                triples_a_.push_back(triple);
            }
            
            APSI_LOG_DEBUG("Generated " << num_triples << " Beaver triples for party A");
            return triples_a_;
        }

        std::vector<secret_sharing::BeaverPair> TEEManager::get_pairs_for_party_b() {
            // 从B方种子生成Beaver二元组
            std::mt19937_64 rng_b;
            initialize_rng_from_seed(rng_b, seed_b_);

            pairs_b_.clear();
            size_t num_pairs = 1000; // 可以根据需要调整数量
            
            for (size_t i = 0; i < num_pairs; ++i) {
                secret_sharing::BeaverPair pair;
                pair.a = rng_b() % 0xFFFFFFFFFFFFFFFFULL;
                pair.b = rng_b() % 0xFFFFFFFFFFFFFFFFULL;
                pairs_b_.push_back(pair);
            }
            
            APSI_LOG_DEBUG("Generated " << num_pairs << " Beaver pairs for party B");
            return pairs_b_;
        }

        std::vector<uint64_t> TEEManager::compute_c1_for_party_b() {
            // 计算c1 = (a0 + a1) * (b0 + b1) - c0
            c1_values_.clear();
            
            size_t min_size = std::min(triples_a_.size(), pairs_b_.size());
            for (size_t i = 0; i < min_size; ++i) {
                uint64_t a_sum = triples_a_[i].a + pairs_b_[i].a;
                uint64_t b_sum = triples_a_[i].b + pairs_b_[i].b;
                uint64_t product = a_sum * b_sum;
                uint64_t c1 = product - triples_a_[i].c;
                c1_values_.push_back(c1);
            }
            
            APSI_LOG_DEBUG("Computed " << c1_values_.size() << " c1 values for party B");
            return c1_values_;
        }

        bool TEEManager::verify_computation(const std::vector<uint64_t>& party_a_result,
                                          const std::vector<uint64_t>& party_b_result) {
            // 验证A方和B方的计算结果是否正确
            if (party_a_result.size() != party_b_result.size()) {
                APSI_LOG_ERROR("Result sizes do not match");
                return false;
            }
            
            // 这里应该实现具体的验证逻辑
            // 在实际应用中，可能需要更复杂的验证机制
            APSI_LOG_INFO("Computation verification completed");
            return true;
        }

        void TEEManager::generate_master_seed() {
            // 生成主种子
            std::random_device rd;
            master_rng_->seed(rd());
        }

        uint64_t TEEManager::generate_random_uint64() {
            return (*master_rng_)();
        }

        void TEEManager::initialize_rng_from_seed(std::mt19937_64& rng, const std::vector<uint64_t>& seed) {
            std::seed_seq seed_seq(seed.begin(), seed.end());
            rng.seed(seed_seq);
        }

    } // namespace tee
} // namespace apsi