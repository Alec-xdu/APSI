// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <utility>

// APSI
#include "apsi/log.h"
#include "apsi/secret_sharing_powers.h"
#include "apsi/util/utils.h"

using namespace std;

namespace apsi {
    namespace receiver {
        SecretSharingPowers::SecretSharingPowers(
            vector<uint64_t> values, 
            const PSIParams &params, 
            const PowersDag &pd,
            const vector<secret_sharing::BeaverTriple>& triples)
            : params_(params), 
              mod_(params.seal_params().plain_modulus().value()),
              triples_(triples) {
            compute_powers(move(values), pd);
        }

        void SecretSharingPowers::compute_powers(vector<uint64_t> values, const PowersDag &pd) {
            auto source_powers = pd.source_nodes();

            // 创建SecretSharing实例
            secret_sharing::SecretSharing secret_sharing(params_);

            // 提取需要的幂次
            vector<uint32_t> exponents;
            for (auto &s : source_powers) {
                exponents.push_back(s.power);
            }

            // 使用秘密共享计算所有幂次
            powers_ = secret_sharing.compute_all_powers(values, exponents, triples_);

            vector<uint32_t> powers_vec;
            transform(powers_.begin(), powers_.end(), back_inserter(powers_vec), [](auto &p) {
                return p.first;
            });
            APSI_LOG_DEBUG("Secret sharing powers computed: " << util::to_string(powers_vec));
        }
    } // namespace receiver
} // namespace apsi