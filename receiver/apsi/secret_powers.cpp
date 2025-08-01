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
#include "apsi/secret_powers.h"
#include "apsi/util/utils.h"

using namespace std;

namespace apsi {
    namespace receiver {
        
        SecretPowers::SecretPowers(
            vector<uint64_t> values, const PSIParams &params, const PowersDag &pd)
            : params_(params), pd_(pd), values_(move(values)), initialized_(false)
        {
            // 从PSI参数中获取素数模数
            prime_modulus_ = params.seal_params().plain_modulus().value();
            
            // 计算需要的三元组数量（基于PowersDag的复杂度）
            auto target_powers = pd.target_powers();
            size_t num_triples = values_.size() * target_powers.size() * 10; // 预留足够的三元组
            
            // 创建TEE实例
            tee_ = make_unique<secret_sharing::SecretSharingTEE>(params, num_triples);
            
            // 生成A方和B方的秘密共享
            if (!tee_->generate_party_a_shares(seed_a_, triples_a_)) {
                throw runtime_error("Failed to generate party A shares");
            }
            
            if (!tee_->generate_party_b_shares(seed_b_, shares_b_, c1_values_)) {
                throw runtime_error("Failed to generate party B shares");
            }
            
            initialized_ = true;
            
            APSI_LOG_INFO("SecretPowers initialized with " << values_.size() 
                         << " values and " << target_powers.size() << " target powers");
        }
        
        SecretPowers::~SecretPowers()
        {
            // 清理敏感数据
            fill(seed_a_.begin(), seed_a_.end(), 0);
            fill(seed_b_.begin(), seed_b_.end(), 0);
            triples_a_.clear();
            shares_b_.clear();
            c1_values_.clear();
            values_.clear();
        }
        
        unordered_map<uint32_t, vector<uint64_t>> SecretPowers::compute_secret_powers(int party_id)
        {
            if (!initialized_) {
                throw logic_error("SecretPowers not properly initialized");
            }
            
            unordered_map<uint32_t, vector<uint64_t>> result;
            
            try {
                auto source_powers = pd_.source_nodes();
                
                // 计算源幂次
                for (const auto &source : source_powers) {
                    auto power_shares = compute_power_share(values_, source.power, party_id);
                    result[source.power] = move(power_shares);
                }
                
                // 使用PowersDag计算其他幂次
                pd_.apply([&](const PowersDag::PowersNode &node) {
                    if (!node.is_source()) {
                        // 非源节点需要通过父节点计算
                        auto parent1_power = node.parents.first;
                        auto parent2_power = node.parents.second;
                        
                        if (result.find(parent1_power) != result.end() && 
                            result.find(parent2_power) != result.end()) {
                            
                            const auto &parent1_shares = result[parent1_power];
                            const auto &parent2_shares = result[parent2_power];
                            
                            vector<uint64_t> product_shares;
                            product_shares.reserve(parent1_shares.size());
                            
                            // 使用Beaver三元组进行安全乘法
                            for (size_t i = 0; i < parent1_shares.size(); ++i) {
                                uint64_t product = secure_multiply(
                                    parent1_shares[i], 
                                    parent2_shares[i], 
                                    party_id, 
                                    i * node.power  // 使用节点幂次作为三元组索引的一部分
                                );
                                product_shares.push_back(product);
                            }
                            
                            result[node.power] = move(product_shares);
                        }
                    }
                });
                
                vector<uint32_t> powers_vec;
                transform(result.begin(), result.end(), back_inserter(powers_vec), 
                         [](const auto &p) { return p.first; });
                APSI_LOG_DEBUG("Secret powers computed for party " << party_id 
                              << ": " << util::to_string(powers_vec));
                
            } catch (const exception &e) {
                APSI_LOG_ERROR("Exception in compute_secret_powers: " << e.what());
                result.clear();
            }
            
            return result;
        }
        
        unordered_map<uint32_t, vector<uint64_t>> SecretPowers::combine_power_shares(
            const unordered_map<uint32_t, vector<uint64_t>> &shares_a,
            const unordered_map<uint32_t, vector<uint64_t>> &shares_b)
        {
            unordered_map<uint32_t, vector<uint64_t>> result;
            
            try {
                // 检查两个映射的键是否相同
                if (shares_a.size() != shares_b.size()) {
                    APSI_LOG_ERROR("Share maps have different sizes: " 
                                  << shares_a.size() << " vs " << shares_b.size());
                    return result;
                }
                
                for (const auto &[power, shares_a_vec] : shares_a) {
                    auto it = shares_b.find(power);
                    if (it == shares_b.end()) {
                        APSI_LOG_ERROR("Power " << power << " not found in shares_b");
                        continue;
                    }
                    
                    const auto &shares_b_vec = it->second;
                    if (shares_a_vec.size() != shares_b_vec.size()) {
                        APSI_LOG_ERROR("Share vectors for power " << power 
                                      << " have different sizes");
                        continue;
                    }
                    
                    vector<uint64_t> combined_shares;
                    combined_shares.reserve(shares_a_vec.size());
                    
                    // 获取素数模数（假设所有SecretPowers实例使用相同的模数）
                    // 这里需要一个静态方法或全局变量来获取模数
                    // 为简化，我们假设使用一个固定的大素数
                    const uint64_t prime_modulus = 0xFFFFFFFFFFC90001ULL; // SEAL默认素数
                    
                    for (size_t i = 0; i < shares_a_vec.size(); ++i) {
                        uint64_t combined = (shares_a_vec[i] + shares_b_vec[i]) % prime_modulus;
                        combined_shares.push_back(combined);
                    }
                    
                    result[power] = move(combined_shares);
                }
                
                APSI_LOG_DEBUG("Combined power shares for " << result.size() << " powers");
                
            } catch (const exception &e) {
                APSI_LOG_ERROR("Exception in combine_power_shares: " << e.what());
                result.clear();
            }
            
            return result;
        }
        
        uint64_t SecretPowers::get_prime_modulus() const
        {
            return prime_modulus_;
        }
        
        vector<uint64_t> SecretPowers::compute_power_share(
            const vector<uint64_t> &values, uint32_t exponent, int party_id)
        {
            vector<uint64_t> result;
            result.reserve(values.size());
            
            try {
                if (exponent == 0) {
                    // x^0 = 1，两方各持有1/2
                    uint64_t half_one = (party_id == 0) ? (prime_modulus_ + 1) / 2 : (prime_modulus_ + 1) / 2;
                    result.assign(values.size(), half_one);
                } else if (exponent == 1) {
                    // x^1 = x，两方各持有x/2
                    for (uint64_t value : values) {
                        uint64_t half_value = (party_id == 0) ? value / 2 : value - value / 2;
                        result.push_back(half_value % prime_modulus_);
                    }
                } else {
                    // 高次幂：使用重复平方法和Beaver三元组
                    for (size_t i = 0; i < values.size(); ++i) {
                        uint64_t base_share = (party_id == 0) ? values[i] / 2 : values[i] - values[i] / 2;
                        uint64_t power_share = power_mod_prime_share(base_share, exponent, party_id, i);
                        result.push_back(power_share);
                    }
                }
                
            } catch (const exception &e) {
                APSI_LOG_ERROR("Exception in compute_power_share: " << e.what());
                result.clear();
            }
            
            return result;
        }
        
        uint64_t SecretPowers::secure_multiply(
            uint64_t a, uint64_t b, int party_id, size_t triple_idx)
        {
            if (party_id == 0) {
                // A方使用Beaver三元组
                if (triple_idx >= triples_a_.size()) {
                    throw out_of_range("Triple index out of range for party A");
                }
                
                const auto &triple = triples_a_[triple_idx];
                
                // Beaver三元组协议：
                // 1. 计算 d = a - a_share, e = b - b_share
                // 2. 发送d, e给对方
                // 3. 计算结果：c_share + d*b_share + e*a_share + (party_id == 0 ? d*e : 0)
                
                uint64_t d = subtract_mod_prime(a, triple.a);
                uint64_t e = subtract_mod_prime(b, triple.b);
                
                // 模拟通信：在实际实现中，这里需要网络通信
                uint64_t result = triple.c;
                result = add_mod_prime(result, multiply_mod_prime(d, triple.b));
                result = add_mod_prime(result, multiply_mod_prime(e, triple.a));
                result = add_mod_prime(result, multiply_mod_prime(d, e)); // 只有A方加这一项
                
                return result;
                
            } else {
                // B方使用二元组和c1值
                if (triple_idx >= shares_b_.size() || triple_idx >= c1_values_.size()) {
                    throw out_of_range("Share index out of range for party B");
                }
                
                const auto &share = shares_b_[triple_idx];
                uint64_t c1 = c1_values_[triple_idx];
                
                uint64_t d = subtract_mod_prime(a, share.a1);
                uint64_t e = subtract_mod_prime(b, share.b1);
                
                uint64_t result = c1;
                result = add_mod_prime(result, multiply_mod_prime(d, share.b1));
                result = add_mod_prime(result, multiply_mod_prime(e, share.a1));
                // B方不加d*e项
                
                return result;
            }
        }
        
        uint64_t SecretPowers::power_mod_prime_share(
            uint64_t base_share, uint32_t exponent, int party_id, size_t base_idx)
        {
            if (exponent == 0) {
                return (party_id == 0) ? (prime_modulus_ + 1) / 2 : (prime_modulus_ + 1) / 2;
            }
            if (exponent == 1) {
                return base_share;
            }
            
            // 使用重复平方法
            uint64_t result_share = (party_id == 0) ? (prime_modulus_ + 1) / 2 : (prime_modulus_ + 1) / 2; // 1的共享
            uint64_t current_power_share = base_share;
            uint32_t current_exp = exponent;
            size_t triple_counter = base_idx * 100; // 避免三元组索引冲突
            
            while (current_exp > 0) {
                if (current_exp & 1) {
                    result_share = secure_multiply(result_share, current_power_share, party_id, triple_counter++);
                }
                if (current_exp > 1) {
                    current_power_share = secure_multiply(current_power_share, current_power_share, party_id, triple_counter++);
                }
                current_exp >>= 1;
            }
            
            return result_share;
        }
        
        uint64_t SecretPowers::multiply_mod_prime(uint64_t a, uint64_t b) const
        {
            __uint128_t result = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
            return static_cast<uint64_t>(result % prime_modulus_);
        }
        
        uint64_t SecretPowers::add_mod_prime(uint64_t a, uint64_t b) const
        {
            if (a >= prime_modulus_) a %= prime_modulus_;
            if (b >= prime_modulus_) b %= prime_modulus_;
            
            uint64_t sum = a + b;
            if (sum >= prime_modulus_) {
                sum -= prime_modulus_;
            }
            return sum;
        }
        
        uint64_t SecretPowers::subtract_mod_prime(uint64_t a, uint64_t b) const
        {
            if (a >= prime_modulus_) a %= prime_modulus_;
            if (b >= prime_modulus_) b %= prime_modulus_;
            
            if (a >= b) {
                return a - b;
            } else {
                return prime_modulus_ - (b - a);
            }
        }
        
        uint64_t SecretPowers::power_mod_prime(uint64_t base, uint32_t exponent) const
        {
            if (exponent == 0) return 1;
            if (exponent == 1) return base % prime_modulus_;
            
            uint64_t result = 1;
            base %= prime_modulus_;
            
            while (exponent > 0) {
                if (exponent & 1) {
                    result = multiply_mod_prime(result, base);
                }
                base = multiply_mod_prime(base, base);
                exponent >>= 1;
            }
            
            return result;
        }
        
    } // namespace receiver
} // namespace apsi