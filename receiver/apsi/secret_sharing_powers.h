// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <unordered_map>
#include <vector>

// APSI
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/secret_sharing.h"

namespace apsi {
    namespace receiver {
        class SecretSharingPowers {
        public:
            SecretSharingPowers(
                std::vector<std::uint64_t> values, 
                const PSIParams &params, 
                const PowersDag &pd,
                const std::vector<secret_sharing::BeaverTriple>& triples);

            // 获取计算的多项式幂次结果
            std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> get_powers() const {
                return powers_;
            }

            // 获取用于后续计算的秘密共享数据
            std::vector<secret_sharing::BeaverTriple> get_triples() const {
                return triples_;
            }

        private:
            PSIParams params_;
            uint64_t modulus_;
            std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> powers_;
            std::vector<secret_sharing::BeaverTriple> triples_;

            void compute_powers(std::vector<std::uint64_t> values, const PowersDag &pd);
        };
    } // namespace receiver
} // namespace apsi