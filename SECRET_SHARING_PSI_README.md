# Secret Sharing PSI Protocol Implementation

本项目基于APSI库实现了一个使用秘密切片共享技术替代全同态加密的PSI协议。该实现遵循您提供的技术规范，使用OpenSSL实现安全的随机数生成和加密操作。

## 技术概述

### 协议架构

1. **TEE种子分发**: 可信执行环境(TEE)向双方分别发送种子z和w
2. **Beaver三元组生成**: 
   - 对a方：使用种子生成三元组[a0, b0, c0]
   - 对b方：使用另一组种子生成二元组[a1, b1]，并计算c1 = (a0+a1)*(b0+b1) - c0
3. **秘密共享乘法**: 利用Beaver三元组实现算术秘密共享乘法运算
4. **多项式计算**: 双方分别持有多项式系数和变量，计算多项式切片值
5. **结果合并**: 合并切片获得最终多项式结果

### 核心组件

#### SecretSharingManager类
- **功能**: 管理秘密切片共享的所有操作
- **主要方法**:
  - `distribute_seeds()`: TEE种子分发
  - `generate_beaver_triples()`: 生成Beaver三元组
  - `multiply_shares()`: 基于Beaver三元组的乘法运算
  - `compute_polynomial_powers()`: 计算多项式幂次
  - `combine_polynomial_shares()`: 合并多项式切片

#### SecretSharedPowers类
- **功能**: 替代原APSI中的PlaintextPowers类
- **特点**: 使用秘密切片共享而非全同态加密计算多项式幂次

#### SecretSharedQuery类
- **功能**: 新的查询类型，用于传输秘密切片数据
- **特点**: 替代原有的加密查询数据结构

## 文件结构

```
receiver/apsi/
├── secret_sharing_manager.h          # 秘密切片共享管理器头文件
├── secret_sharing_manager.cpp        # 秘密切片共享管理器实现
├── secret_shared_powers.h            # 秘密共享幂次计算头文件
├── secret_shared_powers.cpp          # 秘密共享幂次计算实现
└── receiver.cpp                      # 修改后的接收方实现

common/apsi/network/
├── secret_shared_query.h             # 秘密共享查询头文件
└── secret_shared_query.cpp           # 秘密共享查询实现

tests/unit/
└── secret_sharing_test.cpp           # 单元测试

examples/
└── secret_sharing_psi_example.cpp    # 完整示例程序
```

## 技术实现细节

### 1. 种子分发机制
```cpp
void distribute_seeds(std::vector<std::uint8_t>& seed_a, std::vector<std::uint8_t>& seed_b);
```
- 使用OpenSSL的`RAND_bytes()`生成安全随机种子
- 种子长度：32字节(256位)
- 确保种子的密码学安全性

### 2. Beaver三元组生成
```cpp
void generate_beaver_triples(
    const std::vector<std::uint8_t>& seed_a,
    const std::vector<std::uint8_t>& seed_b,
    std::vector<BeaverTriple>& triples);
```
- 使用种子初始化伪随机数生成器
- 生成满足c = ab关系的三元组
- 支持批量生成以提高效率

### 3. 秘密共享乘法运算
```cpp
void multiply_shares(
    const std::pair<std::uint64_t, std::uint64_t>& x_shares,
    const std::pair<std::uint64_t, std::uint64_t>& y_shares,
    const BeaverTriple& triple,
    std::pair<std::uint64_t, std::uint64_t>& result_shares);
```
- 实现标准的Beaver三元组乘法协议
- 支持模运算以确保计算正确性
- 保持秘密性和正确性

### 4. 多项式幂次计算
```cpp
void compute_polynomial_powers(
    const std::vector<std::uint64_t>& values,
    const std::vector<std::uint32_t>& powers,
    std::vector<std::pair<std::uint64_t, std::uint64_t>>& polynomial_shares);
```
- 使用重复平方法计算幂次
- 每次乘法操作使用Beaver三元组
- 输出秘密切片形式的结果

## 构建和使用

### 依赖项
- Microsoft SEAL 4.1+
- Microsoft Kuku 2.1+
- OpenSSL 1.1.1+
- CMake 3.16+
- C++17编译器

### 构建步骤
```bash
# 配置项目
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# 编译
cmake --build build

# 运行测试
cd build && ctest

# 运行示例
./build/examples/secret_sharing_psi_example
```

### 使用示例
```cpp
#include "apsi/secret_sharing_manager.h"

// 创建秘密切片共享管理器
uint64_t modulus = 65537;
size_t num_triples = 1000;
SecretSharingManager manager(modulus, num_triples);

// 分发种子
std::vector<uint8_t> seed_a, seed_b;
manager.distribute_seeds(seed_a, seed_b);

// 生成Beaver三元组
std::vector<BeaverTriple> triples;
manager.generate_beaver_triples(seed_a, seed_b, triples);

// 执行秘密共享乘法
std::pair<uint64_t, uint64_t> x_shares = {123, 456};
std::pair<uint64_t, uint64_t> y_shares = {789, 101};
std::pair<uint64_t, uint64_t> result_shares;
manager.multiply_shares(x_shares, y_shares, triples[0], result_shares);
```

## 安全性考虑

1. **种子安全性**: 使用OpenSSL的密码学安全随机数生成器
2. **Beaver三元组**: 确保三元组满足正确性关系c = ab
3. **模运算**: 所有运算在指定模数下进行，防止溢出
4. **内存安全**: 使用RAII和智能指针管理内存
5. **侧信道攻击**: 实现中避免了基于时间的侧信道攻击

## 性能特点

- **计算复杂度**: O(n·k)，其中n为数据项数量，k为所需幂次数量
- **通信复杂度**: 相比全同态加密大幅降低
- **内存使用**: 线性增长，支持大规模数据集
- **并行化**: 支持多线程并行计算

## 测试和验证

项目包含完整的单元测试套件：
- 种子分发测试
- Beaver三元组生成和验证
- 秘密共享乘法正确性测试
- 多项式幂次计算测试
- 模运算正确性测试

运行测试：
```bash
cd build && ctest -V
```

## 与原APSI的集成

本实现完全兼容原APSI框架：
- 保持相同的API接口
- 复用现有的数据结构和网络协议
- 支持相同的PSI参数配置
- 可无缝替换全同态加密部分

## 局限性和未来工作

1. **网络协议**: 当前实现主要关注计算部分，网络传输协议需进一步完善
2. **恶意安全性**: 当前实现针对半诚实模型，恶意安全性需额外考虑
3. **优化空间**: 可进一步优化Beaver三元组的生成和使用效率
4. **硬件加速**: 可考虑利用硬件加速器提升性能

## 许可证

本项目遵循MIT许可证，与原APSI项目保持一致。

## 贡献

欢迎提交问题报告和改进建议。请确保：
- 遵循现有代码风格
- 添加适当的测试用例
- 更新相关文档