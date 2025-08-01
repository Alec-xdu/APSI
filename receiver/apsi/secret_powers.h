// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <unordered_map>
#include <vector>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/secret_sharing_tee.h"

// GSL
#include "gsl/span"

namespace apsi {
    namespace receiver {
        /**
         * SecretPowers类替代PlaintextPowers类
         * 使用基于Beaver三元组的秘密共享代替全同态加密来计算幂次
         */
        class SecretPowers {
        public:
            /**
             * 构造函数
             * @param values 输入值向量
             * @param params PSI参数
             * @param pd PowersDag对象
             */
            SecretPowers(
                std::vector<std::uint64_t> values, 
                const PSIParams &params, 
                const PowersDag &pd);

            /**
             * 析构函数
             */
            ~SecretPowers();

            /**
             * 计算秘密共享的幂次值
             * 这个方法替代了原来的encrypt方法
             * @param party_id 参与方ID (0为A方, 1为B方)
             * @return 计算得到的幂次值的秘密共享
             */
            std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> compute_secret_powers(
                int party_id);

            /**
             * 合并双方的秘密共享得到最终幂次结果
             * @param shares_a A方的幂次共享
             * @param shares_b B方的幂次共享
             * @return 最终的幂次结果
             */
            static std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> combine_power_shares(
                const std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> &shares_a,
                const std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> &shares_b);

            /**
             * 获取TEE实例的引用
             */
            secret_sharing::SecretSharingTEE& get_tee() { return *tee_; }

            /**
             * 获取素数模数
             */
            std::uint64_t get_prime_modulus() const;

        private:
            /**
             * 计算单个幂次的秘密共享值
             * @param values 输入值
             * @param exponent 指数
             * @param party_id 参与方ID
             * @return 幂次值的秘密共享
             */
            std::vector<std::uint64_t> compute_power_share(
                const std::vector<std::uint64_t> &values, 
                std::uint32_t exponent, 
                int party_id);

            /**
             * 使用Beaver三元组进行安全乘法
             * @param a 第一个操作数
             * @param b 第二个操作数
             * @param party_id 参与方ID
             * @param triple_idx 三元组索引
             * @return 乘法结果的秘密共享
             */
            std::uint64_t secure_multiply(
                std::uint64_t a, 
                std::uint64_t b, 
                int party_id, 
                std::size_t triple_idx);

            /**
             * 计算幂次的秘密共享值（使用重复平方法和Beaver三元组）
             */
            std::uint64_t power_mod_prime_share(
                std::uint64_t base_share, 
                std::uint32_t exponent, 
                int party_id, 
                std::size_t base_idx);

            /**
             * 模素数运算辅助函数
             */
            std::uint64_t multiply_mod_prime(std::uint64_t a, std::uint64_t b) const;
            std::uint64_t add_mod_prime(std::uint64_t a, std::uint64_t b) const;
            std::uint64_t subtract_mod_prime(std::uint64_t a, std::uint64_t b) const;
            std::uint64_t power_mod_prime(std::uint64_t base, std::uint32_t exponent) const;

            // PSI参数
            PSIParams params_;

            // PowersDag对象
            PowersDag pd_;

            // 素数模数
            std::uint64_t prime_modulus_;

            // 输入值
            std::vector<std::uint64_t> values_;

            // TEE实例
            std::unique_ptr<secret_sharing::SecretSharingTEE> tee_;

            // A方的种子和三元组
            secret_sharing::Seed seed_a_;
            std::vector<secret_sharing::BeaverTriple> triples_a_;

            // B方的种子和二元组
            secret_sharing::Seed seed_b_;
            std::vector<secret_sharing::BinaryShare> shares_b_;
            std::vector<std::uint64_t> c1_values_;

            // 初始化标志
            bool initialized_;
        };
    } // namespace receiver
} // namespace apsi