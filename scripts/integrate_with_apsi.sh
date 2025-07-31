#!/bin/bash

# 集成脚本：将秘密共享PSI集成到现有APSI项目

set -e

echo "=== Secret Sharing PSI Integration Script ==="

# 检查是否在APSI项目根目录
if [ ! -f "CMakeLists.txt" ] || [ ! -d "receiver" ] || [ ! -d "common" ]; then
    echo "Error: Please run this script from the APSI project root directory"
    exit 1
fi

echo "1. Backing up original files..."

# 备份原始文件
if [ -f "receiver/apsi/plaintext_powers.cpp" ]; then
    cp receiver/apsi/plaintext_powers.cpp receiver/apsi/plaintext_powers.cpp.backup
    echo "  - Backed up plaintext_powers.cpp"
fi

if [ -f "receiver/apsi/plaintext_powers.h" ]; then
    cp receiver/apsi/plaintext_powers.h receiver/apsi/plaintext_powers.h.backup
    echo "  - Backed up plaintext_powers.h"
fi

echo "2. Adding secret sharing files..."

# 复制秘密共享文件
cp common/apsi/secret_sharing.h common/apsi/
cp common/apsi/secret_sharing.cpp common/apsi/
cp common/apsi/tee_manager.h common/apsi/
cp common/apsi/tee_manager.cpp common/apsi/
cp receiver/apsi/secret_sharing_powers.h receiver/apsi/
cp receiver/apsi/secret_sharing_powers.cpp receiver/apsi/

echo "3. Updating CMakeLists.txt..."

# 更新common/apsi/CMakeLists.txt
if [ -f "common/apsi/CMakeLists.txt" ]; then
    # 添加新的源文件
    sed -i '/set(APSI_COMMON_SOURCES/a secret_sharing.cpp\ntee_manager.cpp' common/apsi/CMakeLists.txt
    echo "  - Updated common/apsi/CMakeLists.txt"
fi

# 更新receiver/apsi/CMakeLists.txt
if [ -f "receiver/apsi/CMakeLists.txt" ]; then
    # 添加新的源文件
    sed -i '/set(APSI_RECEIVER_SOURCES/a secret_sharing_powers.cpp' receiver/apsi/CMakeLists.txt
    echo "  - Updated receiver/apsi/CMakeLists.txt"
fi

echo "4. Creating integration example..."

# 创建集成示例
cat > examples/integration_example.cpp << 'EOF'
// Integration example: Using secret sharing instead of homomorphic encryption

#include "apsi/secret_sharing.h"
#include "apsi/tee_manager.h"
#include "apsi/secret_sharing_powers.h"
#include "apsi/psi_params.h"
#include "apsi/powers.h"

using namespace apsi;

int main() {
    // 初始化TEE管理器
    tee::TEEManager tee_manager;
    tee_manager.initialize();
    
    // 分发种子
    auto seed_a = tee_manager.distribute_seed_to_party_a();
    auto seed_b = tee_manager.distribute_seed_to_party_b();
    
    // 生成Beaver三元组
    auto triples_a = tee_manager.get_triples_for_party_a();
    
    // 创建PSI参数
    PSIParams params;
    
    // 创建PowersDag（简化版本）
    PowersDag pd;
    pd.add_power(1);
    pd.add_power(2);
    pd.add_power(4);
    
    // 测试数据
    std::vector<uint64_t> values = {1, 2, 3, 4, 5};
    
    // 使用秘密共享计算多项式幂次（替换原来的全同态加密）
    SecretSharingPowers powers(values, params, pd, triples_a);
    
    // 获取计算结果
    auto computed_powers = powers.get_powers();
    
    std::cout << "Integration successful! Computed " << computed_powers.size() << " powers." << std::endl;
    
    return 0;
}
EOF

echo "5. Updating main CMakeLists.txt..."

# 更新主CMakeLists.txt以包含OpenSSL
if [ -f "CMakeLists.txt" ]; then
    # 检查是否已经包含OpenSSL
    if ! grep -q "find_package(OpenSSL" CMakeLists.txt; then
        # 在适当位置添加OpenSSL
        sed -i '/find_package(SEAL/a find_package(OpenSSL REQUIRED)' CMakeLists.txt
        echo "  - Added OpenSSL dependency to main CMakeLists.txt"
    fi
fi

echo "6. Creating build script..."

# 创建构建脚本
cat > build_secret_sharing.sh << 'EOF'
#!/bin/bash

# 构建秘密共享PSI版本

set -e

echo "Building Secret Sharing PSI..."

# 创建构建目录
mkdir -p build_secret_sharing
cd build_secret_sharing

# 配置项目
cmake -DCMAKE_BUILD_TYPE=Release ..

# 编译
make -j$(nproc)

echo "Build completed successfully!"
echo "You can now run the integration example:"
echo "  ./examples/integration_example"
EOF

chmod +x build_secret_sharing.sh

echo "7. Creating restoration script..."

# 创建恢复脚本
cat > restore_original.sh << 'EOF'
#!/bin/bash

# 恢复原始APSI文件

set -e

echo "Restoring original APSI files..."

if [ -f "receiver/apsi/plaintext_powers.cpp.backup" ]; then
    mv receiver/apsi/plaintext_powers.cpp.backup receiver/apsi/plaintext_powers.cpp
    echo "  - Restored plaintext_powers.cpp"
fi

if [ -f "receiver/apsi/plaintext_powers.h.backup" ]; then
    mv receiver/apsi/plaintext_powers.h.backup receiver/apsi/plaintext_powers.h
    echo "  - Restored plaintext_powers.h"
fi

echo "Original files restored!"
EOF

chmod +x restore_original.sh

echo ""
echo "=== Integration Complete ==="
echo ""
echo "Next steps:"
echo "1. Install OpenSSL if not already installed:"
echo "   sudo apt-get install libssl-dev"
echo ""
echo "2. Build the project:"
echo "   ./build_secret_sharing.sh"
echo ""
echo "3. Run the integration example:"
echo "   ./examples/integration_example"
echo ""
echo "4. To restore original files:"
echo "   ./restore_original.sh"
echo ""
echo "Note: This integration replaces the homomorphic encryption"
echo "      part of APSI with secret sharing. Make sure to test"
echo "      thoroughly before using in production."