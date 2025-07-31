#!/bin/bash

# 秘密共享PSI协议演示脚本

set -e

echo "=== Secret Sharing PSI Protocol Demo ==="
echo ""

# 检查依赖
echo "1. Checking dependencies..."
if ! command -v g++ &> /dev/null; then
    echo "Error: g++ compiler not found. Please install build-essential."
    exit 1
fi

if ! pkg-config --exists openssl; then
    echo "Error: OpenSSL not found. Please install libssl-dev."
    exit 1
fi

echo "✓ Dependencies check passed"
echo ""

# 编译项目
echo "2. Building the project..."
if [ -f "Makefile" ]; then
    make clean
    make all
    echo "✓ Build completed successfully"
else
    echo "Error: Makefile not found. Please run this script from the project root."
    exit 1
fi
echo ""

# 运行测试
echo "3. Running tests..."
if [ -f "test_secret_sharing" ]; then
    ./test_secret_sharing
    echo "✓ All tests passed"
else
    echo "Warning: Test executable not found"
fi
echo ""

# 运行示例
echo "4. Running example..."
if [ -f "secret_sharing_psi_example" ]; then
    echo "Running secret sharing PSI example..."
    ./secret_sharing_psi_example
    echo "✓ Example completed successfully"
else
    echo "Warning: Example executable not found"
fi
echo ""

# 显示性能信息
echo "5. Performance information..."
echo "The secret sharing PSI protocol provides:"
echo "  - Faster computation compared to homomorphic encryption"
echo "  - Lower memory usage"
echo "  - Simplified dependencies (OpenSSL only)"
echo "  - Secure multi-party computation"
echo ""

# 显示使用说明
echo "6. Usage instructions..."
echo "To use this implementation in your own project:"
echo ""
echo "  #include \"apsi/secret_sharing.h\""
echo "  #include \"apsi/tee_manager.h\""
echo ""
echo "  // Initialize TEE manager"
echo "  tee::TEEManager tee_manager;"
echo "  tee_manager.initialize();"
echo ""
echo "  // Distribute seeds"
echo "  auto seed_a = tee_manager.distribute_seed_to_party_a();"
echo "  auto seed_b = tee_manager.distribute_seed_to_party_b();"
echo ""
echo "  // Generate Beaver triples"
echo "  auto triples_a = tee_manager.get_triples_for_party_a();"
echo ""
echo "  // Create secret sharing instance"
echo "  secret_sharing::SecretSharing secret_sharing(params);"
echo ""
echo "  // Compute polynomial powers"
echo "  auto result = secret_sharing.compute_polynomial_powers(values, exponent, triples);"
echo ""

# 显示集成说明
echo "7. Integration with APSI..."
echo "To integrate with existing APSI project:"
echo "  ./scripts/integrate_with_apsi.sh"
echo ""
echo "To restore original files:"
echo "  ./restore_original.sh"
echo ""

echo "=== Demo completed successfully ==="
echo ""
echo "For more information, see:"
echo "  - README_SecretSharing.md"
echo "  - IMPLEMENTATION_SUMMARY.md"
echo ""
echo "Thank you for using Secret Sharing PSI Protocol!"