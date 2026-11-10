# anyst

固定目标的 TCP/TLS 与 UDP/QUIC 端口转发程序。采用 AnyTLS 风格的 TCP 帧、会话复用和填充，以及 TUIC v5 风格的 UDP association、分片与 TLS exporter 认证。

**不是官方 AnyTLS/TUIC 的完整互操作实现**：两端应使用相同版本的 anyst。目的地址由服务端配置决定，不提供 SOCKS 动态选址。旧版本关闭处理存在缺陷，新版本的 TCP 半关闭与 UDP 回收通知要求两端同步升级。QUIC 认证在握手完成后发送，不是 QUIC 0-RTT。TCP 的 FIN 表示写方向半关闭；另一方向可以继续传输，最多等待 60 秒完成。

填充只控制逻辑 TLS 明文写入，不能保证 TLS record 或网络包的边界，也不保证消除所有嵌套 TLS 特征。默认仅客户端到服务端方向填充。

## 配置

参见 `config.example.yaml`：

- `cert` 和 `key` 必须一起提供，表示服务端；都不提供表示客户端。
- 客户端只配置一个 remote；服务端可配置多个目标，每个目标使用不同密码。
- `remotes` 与旧版 `remote`/`password` 不能混用。重复密码、未知字段、无效地址和空隧道列表会在启动前报错。
- 地址使用 `host:port`，IPv6 使用 `[address]:port`。
- 客户端默认验证系统信任根和服务端名字。`sni` 应匹配证书，留空则从 remote 提取主机名。`insecure: true` 仅用于明确接受风险的自签测试环境。
- 示例密码只是占位符。部署前为目标设置独立高强度随机密码，并在两端配置一致；不要使用安装脚本中的公开固定密码。

UDP 按本地源地址分配独立 association，双方向流量均刷新活跃时间；空闲 60 秒后回收。进程使用共享连接及分片内存预算（512 个 socket 名额、8 MiB 分片/重组记账），每条连接也有流/association 上限；达到上限时拒绝新连接/关联，而不是无限分配。association ID 在同一 QUIC 连接内不复用，耗尽后重新连接。

## 服务与日志

`anyst.service` 使用非 root 的 `anyst` 账号，并允许绑定低端口。**本轮未修改安装脚本，现有脚本需要由维护者适配以下步骤后才能使用新服务模板**：

1. 安装 `anyst.sysusers` 为 `/usr/lib/sysusers.d/anyst.conf`，执行 `systemd-sysusers` 创建账号。
2. 二进制由 root 持有；配置与私钥设置为 `root:anyst`、权限 `0640`，所在目录允许 anyst 遍历。不要赋予服务写入二进制、配置或私钥的权限。
3. 安装服务模板并重新加载 systemd。模板需要支持 `LogsDirectory` 等加固选项的 systemd，不适用于 OpenRC。

程序处理 SIGINT/SIGTERM，并监督所有隧道任务；任一监听器意外退出会停止其他隧道并返回失败，使 systemd 可以重启，不会继续显示一个无监听任务的健康进程。

日志同时写入 stderr 和每日轮转文件，保留最多 7 个文件。不输出密码、密码哈希或对端原始 settings/alert。文件目录通过 `ANYST_LOG_DIR` 配置，默认当前目录；服务模板使用 `/var/log/anyst`。systemd 环境优先通过 journal 查看日志。`RUST_LOG` 可以覆盖配置日志级别。

## 开发与发布

发布使用 Cargo.lock 锁定依赖及 ring TLS provider，不需要 vendored OpenSSL；YAML 解析改用 `serde_yaml_ng`，保留原有调用接口。源码包含半关闭、帧读取、流 ID、分片隔离、规则校验和任务取消的回归测试；CI 在后续提交时运行 Clippy 和测试，发布构建使用 `--locked`。

## 一键脚本（由维护者单独维护）

```bash
bash <(curl -sSL https://raw.githubusercontent.com/bryet/anyst/main/anyst.sh)
```

国内镜像：

```bash
bash <(curl -sSL https://gh-proxy.org/raw.githubusercontent.com/bryet/anyst/main/anyst.sh) v0.1.4
```

执行 root 安装脚本前，应先检查脚本来源及内容，并确认账号创建、证书权限、随机密码和下载校验已适配。脚本当前状态不能代表上述运行程序的默认安全配置。
