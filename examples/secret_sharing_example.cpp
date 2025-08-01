// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

/**
 * 这个示例展示如何使用基于秘密共享的新协议替代APSI中的全同态加密部分
 * 
 * 主要步骤：
 * 1. 初始化PSI参数和PowersDag
 * 2. 创建SecretSharingTEE实例进行秘密切片分发
 * 3. 双方分别使用SecretPowers计算多项式切片
 * 4. 合并切片得到最终结果
 */

// STD
#include <iostream>
#include <vector>
#include <chrono>

// APSI
#include "apsi/psi_params.h"
#include "apsi/powers.h"
#include "apsi/secret_sharing_tee.h"
#include "apsi/secret_powers.h"
#include "apsi/log.h"

using namespace std;
using namespace apsi;
using namespace apsi::secret_sharing;
using namespace apsi::receiver;

int main()
{
    try {
        cout << "=== APSI Secret Sharing Example ===" << endl;
        
        // 1. 初始化PSI参数
        PSIParams params;
        // 这里需要根据实际需求配置参数
        // params.set_table_params({...});
        // params.set_query_params({...});
        // params.set_seal_params({...});
        
        cout << "PSI parameters initialized" << endl;
        
        // 2. 配置PowersDag
        PowersDag pd;
        set<uint32_t> source_powers = {1, 2, 3};  // 源幂次
        set<uint32_t> target_powers = {1, 2, 3, 4, 5, 6};  // 目标幂次
        
        if (!pd.configure(source_powers, target_powers)) {
            cerr << "Failed to configure PowersDag" << endl;
            return 1;
        }
        
        cout << "PowersDag configured with depth " << pd.depth() << endl;
        
        // 3. 准备测试数据
        vector<uint64_t> test_values = {100, 200, 300, 400, 500};
        cout << "Test values: ";
        for (auto val : test_values) {
            cout << val << " ";
        }
        cout << endl;
        
        // 4. 创建SecretPowers实例（模拟A方和B方）
        cout << "\n=== Creating SecretPowers instances ===" << endl;
        
        auto start_time = chrono::high_resolution_clock::now();
        
        // A方的SecretPowers实例
        SecretPowers secret_powers_a(test_values, params, pd);
        cout << "Party A SecretPowers created" << endl;
        
        // B方的SecretPowers实例（使用相同的数据和参数）
        SecretPowers secret_powers_b(test_values, params, pd);
        cout << "Party B SecretPowers created" << endl;
        
        // 5. 双方分别计算秘密共享的幂次
        cout << "\n=== Computing secret power shares ===" << endl;
        
        auto shares_a = secret_powers_a.compute_secret_powers(0);  // A方
        cout << "Party A computed " << shares_a.size() << " power shares" << endl;
        
        auto shares_b = secret_powers_b.compute_secret_powers(1);  // B方
        cout << "Party B computed " << shares_b.size() << " power shares" << endl;
        
        // 6. 合并双方的秘密共享得到最终结果
        cout << "\n=== Combining power shares ===" << endl;
        
        auto final_powers = SecretPowers::combine_power_shares(shares_a, shares_b);
        cout << "Combined power shares for " << final_powers.size() << " powers" << endl;
        
        // 7. 显示结果
        cout << "\n=== Results ===" << endl;
        for (const auto &[power, values] : final_powers) {
            cout << "Power " << power << ": ";
            for (size_t i = 0; i < min(values.size(), size_t(5)); ++i) {
                cout << values[i] << " ";
            }
            if (values.size() > 5) {
                cout << "... (" << values.size() << " total)";
            }
            cout << endl;
        }
        
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        
        cout << "\n=== Performance ===" << endl;
        cout << "Total execution time: " << duration.count() << " ms" << endl;
        cout << "Number of test values: " << test_values.size() << endl;
        cout << "Number of target powers: " << target_powers.size() << endl;
        
        // 8. 验证结果正确性（可选）
        cout << "\n=== Verification ===" << endl;
        
        // 对于小的测试数据，我们可以验证结果的正确性
        uint64_t prime_modulus = secret_powers_a.get_prime_modulus();
        cout << "Prime modulus: " << prime_modulus << endl;
        
        // 验证第一个值的各个幂次
        if (!test_values.empty() && !final_powers.empty()) {
            uint64_t base_value = test_values[0];
            cout << "Verifying powers of " << base_value << ":" << endl;
            
            for (const auto &[power, computed_values] : final_powers) {
                if (!computed_values.empty()) {
                    uint64_t computed = computed_values[0];
                    
                    // 计算期望值
                    uint64_t expected = 1;
                    uint64_t temp_base = base_value % prime_modulus;
                    for (uint32_t i = 0; i < power; ++i) {
                        expected = ((__uint128_t)expected * temp_base) % prime_modulus;
                    }
                    
                    cout << "  " << base_value << "^" << power 
                         << " = " << computed 
                         << " (expected: " << expected << ")";
                    
                    if (computed == expected) {
                        cout << " ✓" << endl;
                    } else {
                        cout << " ✗" << endl;
                    }
                }
            }
        }
        
        cout << "\n=== Example completed successfully ===" << endl;
        return 0;
        
    } catch (const exception &e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }
}

/**
 * 编译和运行说明：
 * 
 * 1. 确保已安装OpenSSL开发库：
 *    sudo apt-get install libssl-dev
 * 
 * 2. 编译命令（需要链接OpenSSL和APSI库）：
 *    g++ -std=c++17 -O2 -I/path/to/apsi/include \
 *        secret_sharing_example.cpp \
 *        -L/path/to/apsi/lib -lapsi \
 *        -lssl -lcrypto \
 *        -o secret_sharing_example
 * 
 * 3. 运行：
 *    ./secret_sharing_example
 * 
 * 注意：这个示例需要完整的APSI库环境才能编译运行。
 * 在实际使用中，还需要考虑网络通信、错误处理等额外因素。
 */