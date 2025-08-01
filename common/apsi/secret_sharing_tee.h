// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <cstdint>
#include <memory>
#include <vector>
#include <unordered_map>

// OpenSSL
#include <openssl/rand.h>
#include <openssl/sha.h>

// APSI
#include "apsi/psi_params.h"
#include "apsi/powers.h"

namespace apsi {
    namespace secret_sharing {
        
        /**
         * Beaver三元组结构，用于算数秘密共享乘法运算
         */
        struct BeaverTriple {
            std::uint64_t a;  // 第一个随机值
            std::uint64_t b;  // 第二个随机值
            std::uint64_t c;  // c = a * b (mod prime)
            
            BeaverTriple() : a(0), b(0), c(0) {}
            BeaverTriple(std::uint64_t a_val, std::uint64_t b_val, std::uint64_t c_val)
                : a(a_val), b(b_val), c(c_val) {}
        };
        
        /**
         * 二元组结构，用于B方的秘密切片
         */
        struct BinaryShare {
            std::uint64_t a1;  // a的切片
            std::uint64_t b1;  // b的切片
            
            BinaryShare() : a1(0), b1(0) {}
            BinaryShare(std::uint64_t a1_val, std::uint64_t b1_val)
                : a1(a1_val), b1(b1_val) {}
        };
        
        /**
         * RNG种子结构
         */
        using Seed = std::array<unsigned char, 32>;
        
        /**
         * TEE类，负责秘密切片分发和Beaver三元组生成
         * 替换APSI中的全同态加密部分
         */
        class SecretSharingTEE {
        public:
            /**
             * 构造函数
             * @param params PSI参数
             * @param num_triples 需要生成的三元组数量
             */
            SecretSharingTEE(const PSIParams &params, std::size_t num_triples);
            
            /**
             * 析构函数
             */
            ~SecretSharingTEE();
            
            /**
             * 为A方生成RNG种子和三元组
             * @param seed_a 输出：A方的RNG种子
             * @param triples_a 输出：A方的Beaver三元组列表
             * @return 成功返回true
             */
            bool generate_party_a_shares(Seed &seed_a, std::vector<BeaverTriple> &triples_a);
            
            /**
             * 为B方生成RNG种子和二元组
             * @param seed_b 输出：B方的RNG种子
             * @param shares_b 输出：B方的二元组列表
             * @param c1_values 输出：B方的c1值列表
             * @return 成功返回true
             */
            bool generate_party_b_shares(Seed &seed_b, std::vector<BinaryShare> &shares_b, 
                                       std::vector<std::uint64_t> &c1_values);
            
            /**
             * 计算多项式切片值
             * @param party_id 参与方ID (0为A方, 1为B方)
             * @param polynomial_coeffs 多项式系数
             * @param variable_values 变量值
             * @param triples_a A方的三元组（如果是A方）
             * @param shares_b B方的二元组（如果是B方）
             * @param c1_values B方的c1值（如果是B方）
             * @return 多项式切片值
             */
            std::vector<std::uint64_t> compute_polynomial_shares(
                int party_id,
                const std::vector<std::uint64_t> &polynomial_coeffs,
                const std::vector<std::uint64_t> &variable_values,
                const std::vector<BeaverTriple> &triples_a = {},
                const std::vector<BinaryShare> &shares_b = {},
                const std::vector<std::uint64_t> &c1_values = {}
            );
            
            /**
             * 合并双方的多项式切片值得到最终结果
             * @param shares_a A方的切片值
             * @param shares_b B方的切片值
             * @return 最终的多项式结果
             */
            std::vector<std::uint64_t> combine_polynomial_shares(
                const std::vector<std::uint64_t> &shares_a,
                const std::vector<std::uint64_t> &shares_b
            );
            
            /**
             * 获取素数模数
             */
            std::uint64_t get_prime_modulus() const { return prime_modulus_; }
            
        private:
            /**
             * 生成安全随机种子
             */
            bool generate_random_seed(Seed &seed);
            
            /**
             * 使用种子初始化PRNG
             */
            void init_prng_with_seed(const Seed &seed);
            
            /**
             * 生成模素数的随机数
             */
            std::uint64_t generate_random_mod_prime();
            
            /**
             * 模素数乘法
             */
            std::uint64_t multiply_mod_prime(std::uint64_t a, std::uint64_t b) const;
            
            /**
             * 模素数加法
             */
            std::uint64_t add_mod_prime(std::uint64_t a, std::uint64_t b) const;
            
            /**
             * 模素数减法
             */
            std::uint64_t subtract_mod_prime(std::uint64_t a, std::uint64_t b) const;
            
            // PSI参数
            PSIParams params_;
            
            // 素数模数
            std::uint64_t prime_modulus_;
            
            // 需要生成的三元组数量
            std::size_t num_triples_;
            
            // A方的种子和三元组（TEE内部存储）
            Seed seed_a_;
            std::vector<BeaverTriple> triples_a_;
            
            // B方的种子和二元组（TEE内部存储）
            Seed seed_b_;
            std::vector<BinaryShare> shares_b_;
            std::vector<std::uint64_t> c1_values_;
            
            // 初始化标志
            bool initialized_;
        };
        
    } // namespace secret_sharing
} // namespace apsi