// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <vector>
#include <memory>
#include <random>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>

// APSI
#include "apsi/secret_sharing.h"

namespace apsi {
    namespace tee {
        
        // TEE管理器类，模拟可信执行环境
        class TEEManager {
        public:
            TEEManager();
            ~TEEManager();

            // 禁用拷贝构造和赋值
            TEEManager(const TEEManager&) = delete;
            TEEManager& operator=(const TEEManager&) = delete;

            // 初始化TEE
            void initialize();

            // 为A方生成和分发种子
            std::vector<uint64_t> distribute_seed_to_party_a();

            // 为B方生成和分发种子
            std::vector<uint64_t> distribute_seed_to_party_b();

            // 获取A方的Beaver三元组
            std::vector<secret_sharing::BeaverTriple> get_triples_for_party_a();

            // 获取B方的Beaver二元组
            std::vector<secret_sharing::BeaverPair> get_pairs_for_party_b();

            // 计算B方的c1值
            std::vector<uint64_t> compute_c1_for_party_b();

            // 验证计算结果的正确性
            bool verify_computation(const std::vector<uint64_t>& party_a_result,
                                  const std::vector<uint64_t>& party_b_result);

        private:
            std::unique_ptr<std::mt19937_64> master_rng_;
            std::vector<uint64_t> seed_a_;
            std::vector<uint64_t> seed_b_;
            std::vector<secret_sharing::BeaverTriple> triples_a_;
            std::vector<secret_sharing::BeaverPair> pairs_b_;
            std::vector<uint64_t> c1_values_;
            
            // OpenSSL相关
            EVP_CIPHER_CTX* cipher_ctx_;

            // 辅助函数
            void generate_master_seed();
            uint64_t generate_random_uint64();
            void initialize_rng_from_seed(std::mt19937_64& rng, const std::vector<uint64_t>& seed);
        };

    } // namespace tee
} // namespace apsi