# APSI 秘密共享扩展

本扩展为APSI库实现了基于秘密共享的新协议，替代原有的全同态加密部分，使用Beaver三元组进行安全的多项式计算。

## 概述

### 原有架构
APSI原本使用全同态加密(FHE)来计算多项式的幂次，这在`receiver/apsi/plaintext_powers.cpp`中实现。

### 新架构
新的实现使用基于Beaver三元组的秘密共享：
- **TEE（可信执行环境）**：负责生成和分发秘密切片
- **双方协作**：A方和B方分别持有秘密切片，协作计算多项式
- **安全乘法**：使用Beaver三元组实现安全的乘法运算

## 核心组件

### 1. SecretSharingTEE 类
位置：`common/apsi/secret_sharing_tee.h/cpp`

**功能**：
- 生成安全的RNG种子
- 为A方生成Beaver三元组 `[a0, b0, c0]`
- 为B方生成二元组 `[a1, b1]` 和计算 `c1 = (a0+a1)*(b0+b1) - c0`
- 提供模运算和多项式计算的基础设施

**主要方法**：
```cpp
bool generate_party_a_shares(Seed &seed_a, std::vector<BeaverTriple> &triples_a);
bool generate_party_b_shares(Seed &seed_b, std::vector<BinaryShare> &shares_b, 
                             std::vector<std::uint64_t> &c1_values);
```

### 2. SecretPowers 类
位置：`receiver/apsi/secret_powers.h/cpp`

**功能**：
- 替代原有的`PlaintextPowers`类
- 使用秘密共享计算多项式的幂次
- 支持PowersDag的所有功能

**主要方法**：
```cpp
std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> compute_secret_powers(int party_id);
static std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> combine_power_shares(
    const std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> &shares_a,
    const std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> &shares_b);
```

## 协议流程

### 1. 初始化阶段
```cpp
// 创建PSI参数和PowersDag
PSIParams params;
PowersDag pd;
pd.configure(source_powers, target_powers);

// 创建SecretPowers实例
SecretPowers secret_powers_a(values, params, pd);  // A方
SecretPowers secret_powers_b(values, params, pd);  // B方
```

### 2. 秘密切片生成
TEE自动完成：
- 生成随机种子 `z` 和 `w`
- A方获得：种子 `z` 和三元组 `[a0, b0, c0]`
- B方获得：种子 `w`、二元组 `[a1, b1]` 和 `c1` 值

### 3. 多项式计算
```cpp
// 双方分别计算秘密共享
auto shares_a = secret_powers_a.compute_secret_powers(0);  // A方
auto shares_b = secret_powers_b.compute_secret_powers(1);  // B方

// 合并得到最终结果
auto final_result = SecretPowers::combine_power_shares(shares_a, shares_b);
```

### 4. Beaver三元组乘法协议
对于乘法 `x * y`：
1. A方计算：`d = x - a0`, `e = y - b0`
2. B方计算：`d = x - a1`, `e = y - b1`
3. 双方交换 `d` 和 `e`
4. A方计算：`result_a = c0 + d*b0 + e*a0 + d*e`
5. B方计算：`result_b = c1 + d*b1 + e*a1`
6. 最终结果：`result = result_a + result_b`

## 安全性保证

### 1. 信息理论安全
- 单独的秘密切片不泄露任何信息
- 只有合并双方切片才能得到真实值

### 2. Beaver三元组的安全性
- 三元组 `(a, b, c)` 满足 `c = a * b`
- 随机性保证了乘法过程的安全性

### 3. TEE保护
- 种子生成和切片分发在可信环境中进行
- 防止恶意方获取对方的秘密信息

## 性能特点

### 优势
- **无需FHE**：避免了全同态加密的高计算开销
- **线性复杂度**：大部分运算是模运算，效率高
- **并行友好**：多个幂次可以并行计算

### 开销
- **通信成本**：需要交换 `d` 和 `e` 值
- **预计算**：需要预生成足够的Beaver三元组
- **存储**：需要存储三元组和种子

## 使用示例

参见 `examples/secret_sharing_example.cpp`：

```cpp
#include "apsi/secret_sharing_tee.h"
#include "apsi/secret_powers.h"

// 初始化
PSIParams params;
PowersDag pd;
std::vector<uint64_t> values = {100, 200, 300};

// 创建实例
SecretPowers powers_a(values, params, pd);
SecretPowers powers_b(values, params, pd);

// 计算和合并
auto shares_a = powers_a.compute_secret_powers(0);
auto shares_b = powers_b.compute_secret_powers(1);
auto result = SecretPowers::combine_power_shares(shares_a, shares_b);
```

## 编译要求

### 依赖库
- **OpenSSL**：用于随机数生成和加密操作
- **APSI**：原有的APSI库组件
- **C++17**：支持现代C++特性

### 编译命令
```bash
# 安装OpenSSL开发库
sudo apt-get install libssl-dev

# 编译（添加OpenSSL链接）
g++ -std=c++17 -O2 \
    -I/path/to/apsi/include \
    your_code.cpp \
    -L/path/to/apsi/lib -lapsi \
    -lssl -lcrypto \
    -o your_program
```

## 集成指南

### 1. 替换PlaintextPowers
在需要使用多项式幂次计算的地方：

```cpp
// 原有代码
PlaintextPowers pp(values, params, pd);
auto encrypted_powers = pp.encrypt(crypto_context);

// 新代码
SecretPowers sp_a(values, params, pd);
SecretPowers sp_b(values, params, pd);
auto shares_a = sp_a.compute_secret_powers(0);
auto shares_b = sp_b.compute_secret_powers(1);
auto final_powers = SecretPowers::combine_power_shares(shares_a, shares_b);
```

### 2. 网络通信
在实际部署中，需要添加网络通信代码来交换：
- Beaver三元组协议中的 `d` 和 `e` 值
- 最终的秘密切片合并

### 3. 错误处理
建议添加完善的错误处理：
- 验证三元组的正确性
- 检查网络通信的完整性
- 处理TEE不可用的情况

## 测试和验证

### 单元测试
可以添加测试验证：
- Beaver三元组的正确性
- 模运算的准确性
- 多项式计算的一致性

### 性能测试
建议测试：
- 不同数据规模下的性能表现
- 与原有FHE方案的性能对比
- 内存使用情况

## 注意事项

1. **网络安全**：实际部署时需要使用安全的通信信道
2. **TEE要求**：需要可信的执行环境来生成种子和切片
3. **随机性**：确保OpenSSL的随机数生成器正确初始化
4. **模数选择**：使用与SEAL兼容的素数模数
5. **内存清理**：及时清理敏感数据（种子、三元组等）

## 扩展可能

1. **批处理优化**：支持批量处理多个多项式
2. **网络优化**：减少通信轮次和数据量
3. **硬件加速**：利用专用硬件加速模运算
4. **动态三元组生成**：根据需要动态生成三元组

## 贡献

欢迎提交问题报告和改进建议。在提交代码时，请确保：
- 遵循现有的代码风格
- 添加适当的测试用例
- 更新相关文档