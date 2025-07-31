// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iostream>
#include <vector>
#include <random>
#include <chrono>

// APSI
#include "apsi/secret_sharing.h"
#include "apsi/tee_manager.h"
#include "apsi/psi_params.h"
#include "apsi/log.h"

using namespace std;
using namespace apsi;

// 模拟A方的计算
class PartyA {
public:
    PartyA(const PSIParams& params, const vector<uint64_t>& seed, 
           const vector<secret_sharing::BeaverTriple>& triples)
        : params_(params), seed_(seed), triples_(triples) {
        
        // 初始化秘密共享
        secret_sharing_ = make_unique<secret_sharing::SecretSharing>(params);
        
        // 从种子生成自己的三元组
        own_triples_ = secret_sharing_->generate_triples_from_seed(seed);
    }

    vector<uint64_t> compute_polynomial_powers(const vector<uint64_t>& values, uint32_t exponent) {
        // 使用秘密共享计算多项式幂次
        return secret_sharing_->compute_polynomial_powers(values, exponent, triples_);
    }

    const vector<secret_sharing::BeaverTriple>& get_triples() const {
        return own_triples_;
    }

private:
    PSIParams params_;
    vector<uint64_t> seed_;
    vector<secret_sharing::BeaverTriple> triples_;
    vector<secret_sharing::BeaverTriple> own_triples_;
    unique_ptr<secret_sharing::SecretSharing> secret_sharing_;
};

// 模拟B方的计算
class PartyB {
public:
    PartyB(const PSIParams& params, const vector<uint64_t>& seed,
           const vector<secret_sharing::BeaverPair>& pairs,
           const vector<uint64_t>& c1_values)
        : params_(params), seed_(seed), pairs_(pairs), c1_values_(c1_values) {
        
        // 初始化秘密共享
        secret_sharing_ = make_unique<secret_sharing::SecretSharing>(params);
        
        // 从种子生成自己的二元组
        own_pairs_ = secret_sharing_->generate_pairs_from_seed(seed);
    }

    vector<uint64_t> compute_polynomial_powers(const vector<uint64_t>& values, uint32_t exponent) {
        // 构建完整的三元组用于计算
        vector<secret_sharing::BeaverTriple> triples;
        size_t min_size = min(pairs_.size(), c1_values_.size());
        
        for (size_t i = 0; i < min_size; ++i) {
            secret_sharing::BeaverTriple triple;
            triple.a = pairs_[i].a;
            triple.b = pairs_[i].b;
            triple.c = c1_values_[i];
            triples.push_back(triple);
        }
        
        // 使用秘密共享计算多项式幂次
        return secret_sharing_->compute_polynomial_powers(values, exponent, triples);
    }

    const vector<secret_sharing::BeaverPair>& get_pairs() const {
        return own_pairs_;
    }

private:
    PSIParams params_;
    vector<uint64_t> seed_;
    vector<secret_sharing::BeaverPair> pairs_;
    vector<uint64_t> c1_values_;
    vector<secret_sharing::BeaverPair> own_pairs_;
    unique_ptr<secret_sharing::SecretSharing> secret_sharing_;
};

int main() {
    try {
        cout << "=== Secret Sharing PSI Protocol Example ===" << endl;

        // 初始化日志
        apsi::Log::SetLogLevel(apsi::Log::Level::info);

        // 创建PSI参数（这里使用默认参数）
        PSIParams params;
        
        // 初始化TEE管理器
        tee::TEEManager tee_manager;
        tee_manager.initialize();

        // TEE为双方分发种子
        cout << "TEE distributing seeds..." << endl;
        auto seed_a = tee_manager.distribute_seed_to_party_a();
        auto seed_b = tee_manager.distribute_seed_to_party_b();

        // TEE生成Beaver三元组和二元组
        cout << "TEE generating Beaver triples and pairs..." << endl;
        auto triples_a = tee_manager.get_triples_for_party_a();
        auto pairs_b = tee_manager.get_pairs_for_party_b();
        auto c1_values = tee_manager.compute_c1_for_party_b();

        // 创建A方和B方
        cout << "Initializing parties..." << endl;
        PartyA party_a(params, seed_a, triples_a);
        PartyB party_b(params, seed_b, pairs_b, c1_values);

        // 生成测试数据
        cout << "Generating test data..." << endl;
        random_device rd;
        mt19937_64 gen(rd());
        uniform_int_distribution<uint64_t> dis(1, 1000);

        vector<uint64_t> test_values(100);
        for (auto& val : test_values) {
            val = dis(gen);
        }

        // 测试多项式幂次计算
        cout << "Testing polynomial power computation..." << endl;
        uint32_t exponent = 5;
        
        auto start_time = chrono::high_resolution_clock::now();
        
        auto result_a = party_a.compute_polynomial_powers(test_values, exponent);
        auto result_b = party_b.compute_polynomial_powers(test_values, exponent);
        
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

        cout << "Computation completed in " << duration.count() << " ms" << endl;
        cout << "Result size: " << result_a.size() << endl;

        // 验证结果
        cout << "Verifying results..." << endl;
        bool verification_result = tee_manager.verify_computation(result_a, result_b);
        
        if (verification_result) {
            cout << "✓ Verification successful!" << endl;
        } else {
            cout << "✗ Verification failed!" << endl;
        }

        // 显示一些结果样本
        cout << "\nSample results:" << endl;
        cout << "Input values: ";
        for (size_t i = 0; i < min(size_t(5), test_values.size()); ++i) {
            cout << test_values[i] << " ";
        }
        cout << "..." << endl;

        cout << "Party A results: ";
        for (size_t i = 0; i < min(size_t(5), result_a.size()); ++i) {
            cout << result_a[i] << " ";
        }
        cout << "..." << endl;

        cout << "Party B results: ";
        for (size_t i = 0; i < min(size_t(5), result_b.size()); ++i) {
            cout << result_b[i] << " ";
        }
        cout << "..." << endl;

        cout << "\n=== Example completed successfully ===" << endl;

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}