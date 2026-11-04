# S-UI 的 veepin 本地补丁

## 来源与范围

- 上游：<https://github.com/wanan9999/veepin>
- 固定版本：`v0.0.0-20261005034428-70e1d01ad0d4`
- 提交：`70e1d01ad0d4`
- 原模块校验和：`h1:WpWkpamXTWo/LuLd8lM0oWY2GQJOEzbo8UmvIiGBZtM=`
- 许可证：MIT，原始声明保留在 `LICENSE`。

本目录仅保留 S-UI 使用的 `l2tp` 包、其递归依赖和对应 Go 测试/README，不是完整的 veepin 产品分支。测试代码额外引用的 `ikev2` 依赖也保留。主模块通过 `replace github.com/wanan9999/veepin => ./deps/veepin` 使用这里的源码，原始依赖版本不变。Dockerfile 必须在读取模块图前复制本目录。

## 补丁

1. `internal/cryptoutil/{dh,modp}.go`：加入 RFC 3526 第 4 节的 MODP-3072（DH15），复用现有 MODP 实现及无效公钥检查。
2. `internal/ikev1/{const,crypto,helpers,sa}.go` 和 `ikuai.go`：L2TP 服务端可接受 DH15，后续 IKE 更新可以复用该组；普通发起端默认提案和其他配置的算法策略不变。
3. `ikuai.go`：只有启用 `ManageLifetime` 的 Main Mode L2TP 服务端收到 `AES-128-CBC / SHA-256 / DH15 / PSK` 时，允许零秒生命周期。运行时使用 `IKELifetime`（未指定时 3600 秒），回复仍保留原始属性；结构检查、重复属性检查、零字节生命周期拒绝、PSK/HASH 校验及过期/更新机制不变。未捕获到的 ESP 零生命周期不作推测性兼容。
4. `ikuai_test.go` 和 `modp3072_test.go`：脱敏提案回归、模数/密钥交换测试、错误 PSK、策略隔离、非法属性和 IKE 更新测试。现有 `tunnelforge_test.go` 的握手辅助函数支持传入第一阶段提案，避免复制整套协议测试。
5. `l2tp/server.go`：IPv4 监听地址（含 `0.0.0.0`）明确使用 `udp4`，避免默认创建 IPv6 双栈 Socket。`server_udp_linux_test.go` 校验 AF_INET 及真实单包/批量接收后的 PKTINFO 回复。此调整是收发路径的受控兼容改进，不代表已证明爱快抓包缺少 MM6 的根因。
6. `internal/ikev1/{session,diagnostics,exchange}.go` 和 `internal/l2tp/server.go`：初次发送、重传发送错误保留原因，超时报告 cookie 和等待阶段；MM5 通过认证且 MM6 成功提交 Socket 后记录状态。日志不输出密钥、认证 HASH 或密文；重试次数、密文重放和认证逻辑不变。成功提交 Socket 不等于对端已经收到。
7. `internal/l2tp/server.go`：每个会话只记录一次源地址不匹配警告、首次准入 IPv4 包及设备写入错误，用于区分 PPP 成功与实际数据转发。源地址限制不放宽，路由器 LAN 流量仍需源 NAT 到 PPP 地址。

提案样本来自用户提供的爱快 3.7.14 抓包，仅保留公开 SA 属性。没有提交原始 PCAP、真实 IP、cookie、用户名或 PSK。第二阶段使用已有的合成 ESP 提案，不能视为爱快真实第二阶段验收。

## 测试

本目录是独立 Go 模块，主模块的 `go test ./...` 不会遍历本目录。须单独执行：

```sh
cd deps/veepin
go test ./internal/cryptoutil ./internal/ikev1 ./internal/l2tp ./l2tp
go test -run 'TestIKuai|TestMODP3072' ./internal/cryptoutil ./internal/ikev1
```

主项目的 L2TP 适配器和完整拨号测试仍使用此替换模块。完整拨号测试必须在隔离 Linux 网络命名空间中运行，不能在生产主机直接启用 `SUI_L2TP_INTEGRATION=1`。

## 更新上游依赖

更新版本时核对上述补丁和回归测试；不能直接覆盖本目录或移除 `replace`，否则可能重新引入爱快的提案拒绝。上游若已提供等效修复，应先运行这些回归和实机验收，再移除此本地替换。
