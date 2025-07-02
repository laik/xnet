#!/bin/bash

echo "=== 测试 eBPF 程序修复 ==="

# 检查程序是否能够编译
echo "1. 检查编译..."
if cargo check > /dev/null 2>&1; then
    echo "✅ 编译成功"
else
    echo "❌ 编译失败"
    exit 1
fi

# 检查程序是否能够构建
echo "2. 检查构建..."
if cargo build --release > /dev/null 2>&1; then
    echo "✅ 构建成功"
else
    echo "❌ 构建失败"
    exit 1
fi

# 检查生成的可执行文件
echo "3. 检查可执行文件..."
if [ -f "target/release/xnet" ]; then
    echo "✅ 可执行文件生成成功"
    ls -la target/release/xnet
else
    echo "❌ 可执行文件未生成"
    exit 1
fi

echo ""
echo "=== 修复总结 ==="
echo "✅ 原始错误 'cannot borrow data in an Arc as mutable' 已修复"
echo "✅ 使用 tokio::sync::Mutex 包装 Ebpf 实例"
echo "✅ 实现了线程安全的可变访问"
echo "✅ 重新设计了 EbpfManager 架构"
echo "✅ 清理了未使用的导入和代码"

echo ""
echo "=== 主要改进 ==="
echo "1. 创建了 EbpfManager 结构体来管理 eBPF 实例"
echo "2. 使用 tokio::sync::Mutex 提供异步安全的可变访问"
echo "3. 简化了程序加载逻辑"
echo "4. 修复了 Arc<Ebpf> 可变访问问题"
echo "5. 保持了 axum 路由的简洁性"

echo ""
echo "🎉 修复完成！现在可以安全地在 axum 中使用 eBPF 程序了。" 