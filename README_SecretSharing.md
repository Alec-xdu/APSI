# Secret Sharing PSI Protocol

这是一个基于秘密切片共享的PSI（Private Set Intersection）协议实现，用于替换APSI中的全同态加密部分。

## 概述

本实现基于Beaver三元组的算术秘密共享，通过可信执行环境（TEE）分发种子，实现安全的多方计算。主要特点：

- 使用OpenSSL进行密码学操作
- 基于Beaver三元组的秘密共享乘法
- TEE模拟器进行种子分发
- 替换原APSI中的全同态加密部分

## 架构

### 核心组件

1. **SecretSharing类** (`common/apsi/secret_sharing.h/cpp`)
   - 实现Beaver三元组生成
   - 秘密共享乘法运算
   - 多项式幂次计算

2. **TEEManager类** (`common/apsi/tee_manager.h/cpp`)
   - 模拟可信执行环境
   - 种子分发
   - Beaver三元组和二元组生成

3. **SecretSharingPowers类** (`receiver/apsi/secret_sharing_powers.h/cpp`)
   - 替换原PlaintextPowers类
   - 基于秘密共享的多项式计算

### 协议流程

1. **初始化阶段**
   - TEE生成主种子
   - 为A方和B方分别生成RNG种子

2. **Beaver三元组生成**
   - A方：使用种子生成三元组 [a0, b0, c0]
   - B方：使用种子生成二元组 [a1, b1]
   - TEE：计算 c1 = (a0 + a1) * (b0 + b1) - c0

3. **秘密共享计算**
   - 双方分别持有数据切片
   - 使用Beaver三元组进行安全乘法
   - 计算多项式幂次

4. **结果合并**
   - 双方交换计算结果
   - 合并获得最终多项式结果

## 编译和安装

### 依赖项

- C++17 编译器
- OpenSSL 1.1.1 或更高版本
- CMake 3.16 或更高版本

### 编译步骤

```bash
# 创建构建目录
mkdir build && cd build

# 配置项目
cmake -DCMAKE_BUILD_TYPE=Release ..

# 编译
make -j$(nproc)

# 安装（可选）
sudo make install
```

### 运行示例

```bash
# 运行示例程序
./secret_sharing_psi_example
```

## 使用方法

### 基本用法

```cpp
#include "apsi/secret_sharing.h"
#include "apsi/tee_manager.h"

// 初始化TEE管理器
tee::TEEManager tee_manager;
tee_manager.initialize();

// 分发种子
auto seed_a = tee_manager.distribute_seed_to_party_a();
auto seed_b = tee_manager.distribute_seed_to_party_b();

// 生成Beaver三元组
auto triples_a = tee_manager.get_triples_for_party_a();
auto pairs_b = tee_manager.get_pairs_for_party_b();
auto c1_values = tee_manager.compute_c1_for_party_b();

// 创建秘密共享实例
secret_sharing::SecretSharing secret_sharing(params);

// 计算多项式幂次
auto result = secret_sharing.compute_polynomial_powers(values, exponent, triples);
```

### 集成到APSI

要替换原APSI中的全同态加密部分：

1. 将 `SecretSharingPowers` 替换 `PlaintextPowers`
2. 在receiver中使用新的秘密共享计算
3. 移除SEAL相关的依赖

```cpp
// 原来的代码
PlaintextPowers powers(values, params, powers_dag);
auto encrypted_powers = powers.encrypt(crypto_context);

// 新的代码
SecretSharingPowers powers(values, params, powers_dag, triples);
auto computed_powers = powers.get_powers();
```

## API 参考

### SecretSharing 类

#### 构造函数
```cpp
SecretSharing(const PSIParams& params);
```

#### 主要方法
```cpp
// 生成种子
std::vector<uint64_t> generate_seed_a();
std::vector<uint64_t> generate_seed_b();

// 从种子生成Beaver三元组
std::vector<BeaverTriple> generate_triples_from_seed(const std::vector<uint64_t>& seed);

// 秘密共享乘法
uint64_t secure_multiply(uint64_t x_share, uint64_t y_share, 
                        const BeaverTriple& triple, uint64_t modulus);

// 多项式幂次计算
std::vector<uint64_t> compute_polynomial_powers(
    const std::vector<uint64_t>& values, 
    uint32_t exponent,
    const std::vector<BeaverTriple>& triples);
```

### TEEManager 类

#### 主要方法
```cpp
// 初始化
void initialize();

// 种子分发
std::vector<uint64_t> distribute_seed_to_party_a();
std::vector<uint64_t> distribute_seed_to_party_b();

// Beaver三元组生成
std::vector<BeaverTriple> get_triples_for_party_a();
std::vector<BeaverPair> get_pairs_for_party_b();
std::vector<uint64_t> compute_c1_for_party_b();
```

## 安全考虑

1. **种子安全**：确保种子在传输和存储过程中的安全性
2. **随机数生成**：使用密码学安全的随机数生成器
3. **模运算**：正确处理大数模运算，避免溢出
4. **内存安全**：及时清理敏感数据

## 性能优化

1. **批量计算**：使用 `compute_all_powers` 进行批量幂次计算
2. **并行处理**：利用多线程进行并行计算
3. **内存管理**：合理分配和释放内存

## 故障排除

### 常见问题

1. **OpenSSL链接错误**
   ```bash
   # 确保正确安装OpenSSL
   sudo apt-get install libssl-dev
   ```

2. **编译错误**
   ```bash
   # 检查C++标准
   # 确保使用C++17或更高版本
   ```

3. **运行时错误**
   ```bash
   # 检查依赖库
   ldd ./secret_sharing_psi_example
   ```

## 贡献

欢迎提交问题和改进建议。请确保：

1. 代码符合项目编码规范
2. 添加适当的测试
3. 更新相关文档

## 许可证

本项目采用MIT许可证，详见LICENSE文件。