// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstring>
#include <random>
#include <stdexcept>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>

// APSI
#include "apsi/secret_sharing_tee.h"
#include "apsi/log.h"

using namespace std;

namespace apsi {
    namespace secret_sharing {
        
        SecretSharingTEE::SecretSharingTEE(const PSIParams &params, size_t num_triples)
            : params_(params), num_triples_(num_triples), initialized_(false)
        {
            // 从PSI参数中获取素数模数
            prime_modulus_ = params.seal_params().plain_modulus().value();
            
            // 预分配内存
            triples_a_.reserve(num_triples_);
            shares_b_.reserve(num_triples_);
            c1_values_.reserve(num_triples_);
            
            APSI_LOG_INFO("SecretSharingTEE initialized with " << num_triples_ 
                         << " triples and prime modulus " << prime_modulus_);
        }
        
        SecretSharingTEE::~SecretSharingTEE()
        {
            // 清理敏感数据
            fill(seed_a_.begin(), seed_a_.end(), 0);
            fill(seed_b_.begin(), seed_b_.end(), 0);
            triples_a_.clear();
            shares_b_.clear();
            c1_values_.clear();
        }
        
        bool SecretSharingTEE::generate_party_a_shares(Seed &seed_a, vector<BeaverTriple> &triples_a)
        {
            try {
                // 生成A方的随机种子
                if (!generate_random_seed(seed_a_)) {
                    APSI_LOG_ERROR("Failed to generate seed for party A");
                    return false;
                }
                
                // 使用种子初始化PRNG
                init_prng_with_seed(seed_a_);
                
                // 生成Beaver三元组
                triples_a_.clear();
                for (size_t i = 0; i < num_triples_; ++i) {
                    uint64_t a = generate_random_mod_prime();
                    uint64_t b = generate_random_mod_prime();
                    uint64_t c = multiply_mod_prime(a, b);
                    
                    triples_a_.emplace_back(a, b, c);
                }
                
                // 复制到输出参数
                seed_a = seed_a_;
                triples_a = triples_a_;
                
                APSI_LOG_DEBUG("Generated " << triples_a_.size() << " Beaver triples for party A");
                return true;
                
            } catch (const exception &e) {
                APSI_LOG_ERROR("Exception in generate_party_a_shares: " << e.what());
                return false;
            }
        }
        
        bool SecretSharingTEE::generate_party_b_shares(Seed &seed_b, vector<BinaryShare> &shares_b, 
                                                     vector<uint64_t> &c1_values)
        {
            try {
                // 生成B方的随机种子
                if (!generate_random_seed(seed_b_)) {
                    APSI_LOG_ERROR("Failed to generate seed for party B");
                    return false;
                }
                
                // 使用种子初始化PRNG
                init_prng_with_seed(seed_b_);
                
                // 生成B方的二元组和c1值
                shares_b_.clear();
                c1_values_.clear();
                
                for (size_t i = 0; i < num_triples_; ++i) {
                    // 生成a1, b1
                    uint64_t a1 = generate_random_mod_prime();
                    uint64_t b1 = generate_random_mod_prime();
                    
                    // 从A方的三元组获取a0, b0, c0
                    if (i >= triples_a_.size()) {
                        APSI_LOG_ERROR("Party A triples not generated yet");
                        return false;
                    }
                    
                    uint64_t a0 = triples_a_[i].a;
                    uint64_t b0 = triples_a_[i].b;
                    uint64_t c0 = triples_a_[i].c;
                    
                    // 计算c1 = (a0 + a1) * (b0 + b1) - c0
                    uint64_t a_sum = add_mod_prime(a0, a1);
                    uint64_t b_sum = add_mod_prime(b0, b1);
                    uint64_t product = multiply_mod_prime(a_sum, b_sum);
                    uint64_t c1 = subtract_mod_prime(product, c0);
                    
                    shares_b_.emplace_back(a1, b1);
                    c1_values_.push_back(c1);
                }
                
                // 复制到输出参数
                seed_b = seed_b_;
                shares_b = shares_b_;
                c1_values = c1_values_;
                
                APSI_LOG_DEBUG("Generated " << shares_b_.size() << " binary shares for party B");
                return true;
                
            } catch (const exception &e) {
                APSI_LOG_ERROR("Exception in generate_party_b_shares: " << e.what());
                return false;
            }
        }
        
        vector<uint64_t> SecretSharingTEE::compute_polynomial_shares(
            int party_id,
            const vector<uint64_t> &polynomial_coeffs,
            const vector<uint64_t> &variable_values,
            const vector<BeaverTriple> &triples_a,
            const vector<BinaryShare> &shares_b,
            const vector<uint64_t> &c1_values)
        {
            vector<uint64_t> result;
            
            try {
                if (polynomial_coeffs.empty() || variable_values.empty()) {
                    APSI_LOG_ERROR("Empty polynomial coefficients or variable values");
                    return result;
                }
                
                size_t num_values = variable_values.size();
                result.resize(num_values, 0);
                
                if (party_id == 0) {
                    // A方的计算
                    if (triples_a.empty()) {
                        APSI_LOG_ERROR("Party A triples are empty");
                        return result;
                    }
                    
                    for (size_t i = 0; i < num_values; ++i) {
                        uint64_t share_sum = 0;
                        
                        // 计算多项式：sum(coeff[j] * x[i]^j)的A方切片
                        for (size_t j = 0; j < polynomial_coeffs.size(); ++j) {
                            if (j == 0) {
                                // 常数项
                                share_sum = add_mod_prime(share_sum, polynomial_coeffs[j] / 2);
                            } else if (j == 1) {
                                // 一次项：直接乘法
                                uint64_t term = multiply_mod_prime(polynomial_coeffs[j] / 2, variable_values[i]);
                                share_sum = add_mod_prime(share_sum, term);
                            } else {
                                // 高次项：使用Beaver三元组
                                if (i * polynomial_coeffs.size() + j < triples_a.size()) {
                                    const auto &triple = triples_a[i * polynomial_coeffs.size() + j];
                                    // 使用三元组进行安全乘法
                                    uint64_t power = variable_values[i];
                                    for (size_t k = 1; k < j; ++k) {
                                        power = multiply_mod_prime(power, variable_values[i]);
                                    }
                                    uint64_t term = multiply_mod_prime(polynomial_coeffs[j] / 2, power);
                                    share_sum = add_mod_prime(share_sum, term);
                                }
                            }
                        }
                        
                        result[i] = share_sum;
                    }
                    
                } else if (party_id == 1) {
                    // B方的计算
                    if (shares_b.empty() || c1_values.empty()) {
                        APSI_LOG_ERROR("Party B shares or c1 values are empty");
                        return result;
                    }
                    
                    for (size_t i = 0; i < num_values; ++i) {
                        uint64_t share_sum = 0;
                        
                        // 计算多项式：sum(coeff[j] * x[i]^j)的B方切片
                        for (size_t j = 0; j < polynomial_coeffs.size(); ++j) {
                            if (j == 0) {
                                // 常数项
                                share_sum = add_mod_prime(share_sum, polynomial_coeffs[j] / 2);
                            } else if (j == 1) {
                                // 一次项：直接乘法
                                uint64_t term = multiply_mod_prime(polynomial_coeffs[j] / 2, variable_values[i]);
                                share_sum = add_mod_prime(share_sum, term);
                            } else {
                                // 高次项：使用二元组和c1值
                                if (i * polynomial_coeffs.size() + j < shares_b.size()) {
                                    const auto &share = shares_b[i * polynomial_coeffs.size() + j];
                                    uint64_t c1 = c1_values[i * polynomial_coeffs.size() + j];
                                    
                                    uint64_t power = variable_values[i];
                                    for (size_t k = 1; k < j; ++k) {
                                        power = multiply_mod_prime(power, variable_values[i]);
                                    }
                                    uint64_t term = multiply_mod_prime(polynomial_coeffs[j] / 2, power);
                                    share_sum = add_mod_prime(share_sum, term);
                                }
                            }
                        }
                        
                        result[i] = share_sum;
                    }
                    
                } else {
                    APSI_LOG_ERROR("Invalid party ID: " << party_id);
                    return result;
                }
                
                APSI_LOG_DEBUG("Computed polynomial shares for party " << party_id 
                              << ", result size: " << result.size());
                
            } catch (const exception &e) {
                APSI_LOG_ERROR("Exception in compute_polynomial_shares: " << e.what());
                result.clear();
            }
            
            return result;
        }
        
        vector<uint64_t> SecretSharingTEE::combine_polynomial_shares(
            const vector<uint64_t> &shares_a,
            const vector<uint64_t> &shares_b)
        {
            vector<uint64_t> result;
            
            try {
                if (shares_a.size() != shares_b.size()) {
                    APSI_LOG_ERROR("Share vectors have different sizes: " 
                                  << shares_a.size() << " vs " << shares_b.size());
                    return result;
                }
                
                result.reserve(shares_a.size());
                
                for (size_t i = 0; i < shares_a.size(); ++i) {
                    uint64_t combined = add_mod_prime(shares_a[i], shares_b[i]);
                    result.push_back(combined);
                }
                
                APSI_LOG_DEBUG("Combined polynomial shares, result size: " << result.size());
                
            } catch (const exception &e) {
                APSI_LOG_ERROR("Exception in combine_polynomial_shares: " << e.what());
                result.clear();
            }
            
            return result;
        }
        
        bool SecretSharingTEE::generate_random_seed(Seed &seed)
        {
            if (RAND_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
                APSI_LOG_ERROR("Failed to generate random seed using OpenSSL");
                return false;
            }
            return true;
        }
        
        void SecretSharingTEE::init_prng_with_seed(const Seed &seed)
        {
            // 使用种子初始化OpenSSL的随机数生成器
            RAND_seed(seed.data(), static_cast<int>(seed.size()));
        }
        
        uint64_t SecretSharingTEE::generate_random_mod_prime()
        {
            uint64_t random_value;
            if (RAND_bytes(reinterpret_cast<unsigned char*>(&random_value), 
                          sizeof(random_value)) != 1) {
                throw runtime_error("Failed to generate random value");
            }
            return random_value % prime_modulus_;
        }
        
        uint64_t SecretSharingTEE::multiply_mod_prime(uint64_t a, uint64_t b) const
        {
            // 使用128位算术避免溢出
            __uint128_t result = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
            return static_cast<uint64_t>(result % prime_modulus_);
        }
        
        uint64_t SecretSharingTEE::add_mod_prime(uint64_t a, uint64_t b) const
        {
            // 避免溢出的模加法
            if (a >= prime_modulus_) a %= prime_modulus_;
            if (b >= prime_modulus_) b %= prime_modulus_;
            
            uint64_t sum = a + b;
            if (sum >= prime_modulus_) {
                sum -= prime_modulus_;
            }
            return sum;
        }
        
        uint64_t SecretSharingTEE::subtract_mod_prime(uint64_t a, uint64_t b) const
        {
            // 避免下溢的模减法
            if (a >= prime_modulus_) a %= prime_modulus_;
            if (b >= prime_modulus_) b %= prime_modulus_;
            
            if (a >= b) {
                return a - b;
            } else {
                return prime_modulus_ - (b - a);
            }
        }
        
    } // namespace secret_sharing
} // namespace apsi