// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <vector>
#include <memory>
#include <random>
#include <unordered_map>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

// APSI
#include "apsi/psi_params.h"

namespace apsi {
    namespace secret_sharing {
        
        // Beaver三元组结构
        struct BeaverTriple {
            uint64_t a;
            uint64_t b;
            uint64_t c;
        };

        // 二元组结构
        struct BeaverPair {
            uint64_t a;
            uint64_t b;
        };

        // 秘密切片共享类
        class SecretSharing {
        public:
            SecretSharing(const PSIParams& params);
            ~SecretSharing();

            // 禁用拷贝构造和赋值
            SecretSharing(const SecretSharing&) = delete;
            SecretSharing& operator=(const SecretSharing&) = delete;

            // 生成种子
            std::vector<uint64_t> generate_seed_a();
            std::vector<uint64_t> generate_seed_b();

            // 从种子生成Beaver三元组和二元组
            std::vector<BeaverTriple> generate_triples_from_seed(const std::vector<uint64_t>& seed);
            std::vector<BeaverPair> generate_pairs_from_seed(const std::vector<uint64_t>& seed);

            // 计算c1 = (a0 + a1) * (b0 + b1) - c0
            uint64_t compute_c1(const BeaverTriple& triple_a, const BeaverPair& pair_b);

            // 基于Beaver三元组的秘密共享乘法
            uint64_t secure_multiply(uint64_t x_share, uint64_t y_share, 
                                   const BeaverTriple& triple, uint64_t modulus);

            // 多项式计算（替换原来的全同态加密幂次计算）
            std::vector<uint64_t> compute_polynomial_powers(
                const std::vector<uint64_t>& values, 
                uint32_t exponent,
                const std::vector<BeaverTriple>& triples);

            // 批量计算多项式幂次
            std::unordered_map<uint32_t, std::vector<uint64_t>> compute_all_powers(
                const std::vector<uint64_t>& values,
                const std::vector<uint32_t>& exponents,
                const std::vector<BeaverTriple>& triples);

        private:
            PSIParams params_;
            uint64_t modulus_;
            
            // OpenSSL相关
            EVP_CIPHER_CTX* cipher_ctx_;
            std::unique_ptr<std::mt19937_64> rng_a_;
            std::unique_ptr<std::mt19937_64> rng_b_;

            // 辅助函数
            uint64_t generate_random_uint64(std::mt19937_64& rng);
            std::vector<uint64_t> generate_random_values(std::mt19937_64& rng, size_t count);
            uint64_t modular_add(uint64_t a, uint64_t b) const;
            uint64_t modular_subtract(uint64_t a, uint64_t b) const;
            uint64_t modular_multiply(uint64_t a, uint64_t b) const;
            void initialize_rng(std::mt19937_64& rng, const std::vector<uint64_t>& seed);
        };

    } // namespace secret_sharing
} // namespace apsi