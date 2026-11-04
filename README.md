# S-UI

### 本版本的 L2TP/IPsec 功能

本版本移植了 [wanan9999/s-ui](https://github.com/wanan9999/s-ui) 的 L2TP 适配器，并保留原版前端的主题和布局。L2TP 依赖基于固定版本的 [wanan9999/veepin](https://github.com/wanan9999/veepin)，所需源码和爱快兼容补丁保存在 `deps/veepin`，通过 `go.mod` 的本地替换参与构建；来源、补丁范围和测试命令见 [依赖说明](deps/veepin/README.s-ui.md)。

1. 在 Linux 上使用现有构建配置编译，这些配置包含 gVisor 支持。添加类型为 **L2TP/IPsec** 的入站。
2. 设置服务器公网 IPv4 地址和 IPsec 预共享密钥（PSK）。默认监听地址为 `0.0.0.0:500`，客户端地址池为 `10.20.0.0/24`；地址池必须是前缀长度介于 `/16` 和 `/29` 之间的私有 IPv4 子网。
3. 在**用户管理**中设置用户的 L2TP 密码，并将用户绑定到该入站。已有用户需要打开用户编辑表单并保存一次，以补充 L2TP 凭据。关闭 L2TP 入站，或没有启用且具备 L2TP 凭据的用户时，入站不会监听。
4. 放行 UDP **500** 和 **4500** 端口，无需对公网开放 UDP 1701。服务端无需安装 strongSwan、xl2tpd 或 pppd，也不依赖 `/dev/net/tun`、主机 NAT 或转发规则。
5. 在操作系统或路由器的 VPN 客户端中手动填写公网 IPv4 地址、PSK、用户名和密码。L2TP 不包含在 sing-box 和 Clash 订阅中。

每个通过认证的会话都会携带用户身份，经由 sing-box 转发 IPv4 TCP/UDP 流量，因此现有流量限制和 `auth_user` 路由规则同样适用。目前不支持 ICMP 和 IPv6 转发。请在客户端配置中阻止隧道外的流量，包括 IPv6 流量。

如需使用面板中的 DNS 配置，请配置 DNS 服务器，并在常规路由规则之前添加一条针对目标端口 53 的 `hijack-dns` 规则。DNS 服务器列表为空时，sing-box 仍可使用隐式的系统 DNS；DNS 劫持无法控制隧道外的流量或客户端的 DoH 请求。

保存 DNS、路由及规则集、HTTP 客户端和出站配置时，会使用策略热更新。在支持的配置下，更新过程会保留 L2TP 监听器、IKE/IPsec/PPP 拨号会话和 gVisor 设备。仅修改 DNS 时，普通 TCP/UDP 连接会保留，现有 DNS 通道会在下一次查询时使用新策略。修改路由或 HTTP 客户端配置会关闭业务连接；修改出站配置会关闭使用受影响依赖链的连接。客户端可以建立新的业务连接，无需重新拨号。

新策略会在数据库提交前完成准备，并在提交后生效。准备或保存失败时，会返回错误并继续运行旧策略。保存操作会等待正在进行的核心启动、停止等操作完成。目前，配置中包含 TUN、端点、核心服务、证书提供程序、核心 API、已启用的 NTP 或持久化核心缓存时，不支持策略热更新。修改其他全局设置（包括日志、证书和命名空间）前，需要先停止核心。维护模式下，保存操作只校验并写入配置，不会启动核心。

修改用户账号仍会重建受影响的入站，并断开该入站的会话。现有核心看门狗会检测监听器故障；维护模式会阻止自动恢复。L2TP 服务端适配器支持 Linux，其他原版支持的平台继续使用其已有协议。

项目包含会话身份、TCP/UDP 转发、MTU 协商、日志、资源作用域清理和凭据选择等测试。Test 工作流还会在隔离的 Linux 网络命名空间中运行策略失败处理、资源归属回归测试，以及完整的 PPP/IPsec 流程测试，其中包括在同一拨号会话中修改 DNS 和路由。这些测试的存在不代表它们已经在当前代码版本中全部通过。实际 Windows 或路由器客户端的兼容性，以及长时间运行中的密钥更新会话，需要另行验收。

### 爱快 3.7.14 的 IKEv1 兼容

该固件的一份拨号抓包仅提供 `AES-128-CBC / SHA-256 / DH15 (MODP 3072) / PSK`，并发送值为 `0` 的秒生命周期。本版本为 L2TP 服务端增加 DH15 支持；仅在已启用生命周期管理的 Main Mode L2TP 服务端收到上述组合时，将零秒值按有限的本地 IKE 生命周期处理（默认 3600 秒）。回复保留原始提案属性，PSK 校验、过期、重协商和非法属性检查仍然有效，未启用 DH2 或 3DES。

依赖中的 `ikuai_test.go` 使用不含地址、cookie 或密钥的提案字节作为回归样本，并包含模拟 Main/Quick Mode、错误 PSK 和 ESP 数据验证。实际爱快的第二阶段提案、PPP 拨号及长时间重协商仍需更新程序后实机验收；这些模拟测试不代表爱快已完成端到端兼容验收。客户端页面的 L2TP 端口仍填 `1701`，公网防火墙放行 UDP `500` 和 `4500`。

服务端的 IPv4 UDP 500/4500 监听明确使用 IPv4 Socket，包括监听 `0.0.0.0` 时；这避免了隐式双栈 Socket，但尚不能仅凭测试认定它解决了所有爱快重拨故障。诊断日志会区分 MM5 认证、MM6 提交发送、等待 QM1/QM3 超时和 UDP 发送错误。出现 `first tunnel IPv4 packet admitted` 仅说明数据进入服务端网络栈；若出现源地址不匹配警告，应检查路由器是否将 LAN 流量源 NAT 到 PPP 地址，不能通过关闭源地址检查绕过。真实拨号、网页访问及重协商需要分别验收。

### 配置保存和更新安全

- TLS、服务、端点及客户端认证变更由同一生命周期锁协调：先写候选数据和审计，再应用运行态并提交。创建或提交失败会尝试恢复旧运行配置；已断开的业务连接/拨号会话不能恢复，恢复失败会返回明确错误，需人工处理。
- 配额停用和流量重置沿用同一协调流程，不会与入站保存或核心启停交错。用户编辑只有显式发送 `resetUsage: true` 才重置用量，不再根据表单中的零计数判断。
- 热更新遇到 Reality/ShadowTLS 等入站持有的原生出站 detour、DNS resolver 或证书提供器引用时，会要求先停止核心，避免使用已回收的策略管理器。无这些引用的 L2TP 策略热更新保持原有范围。
- 前端使用服务端签发的 `revision` 游标轮询配置，不依赖浏览器时间；旧数字游标会触发重新加载。
- 面板升级只检查和下载 `bryet/s-ui` 发行包，保留现有 systemd unit、数据库路径和菜单脚本。更新替换程序及可选 `libcronet.so`；调度失败恢复旧程序，迁移/启动失败时恢复备份程序和 SQLite/WAL/SHM。恢复失败不会强行启动，备份保留在安装目录的 `.update-*` 中。只有用户主动执行更新才会操作这些文件和服务。
- 本轮修复增加了回归用例，但尚未编译或执行测试；更新恢复流程也未在实际 systemd 环境验收，不能把源码修改等同于已验证的运行结果。

**基于 SagerNet/Sing-Box 的高级 Web 管理面板**

![](https://img.shields.io/github/v/release/bryet/s-ui.svg)
![S-UI Docker 拉取次数](https://img.shields.io/docker/pulls/alireza7/s-ui.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/bryet/s-ui)](https://goreportcard.com/report/github.com/bryet/s-ui)
[![下载次数](https://img.shields.io/github/downloads/bryet/s-ui/total.svg)](https://img.shields.io/github/downloads/bryet/s-ui/total.svg)
[![许可证](https://img.shields.io/badge/license-GPL%20V3-blue.svg?longCache=true)](https://www.gnu.org/licenses/gpl-3.0.en.html)

> **免责声明：** 本项目仅用于个人学习和交流，请勿用于非法用途，也请勿在生产环境中使用。

**如果本项目对你有帮助，欢迎点亮一颗星** :star2:

**参与贡献：** 请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)，了解开发环境配置、代码规范、测试和 Pull Request 流程。

[![请作者喝杯咖啡](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/alireza7)

<a href="https://nowpayments.io/donation/alireza7" target="_blank" rel="noreferrer noopener">
   <img src="https://nowpayments.io/images/embeds/donation-button-white.svg" alt="通过 NOWPayments 捐赠加密货币">
</a>

## 功能概览

| 功能 | 是否支持 |
|------|:--------:|
| 多协议 | :heavy_check_mark: |
| 多语言 | :heavy_check_mark: |
| 多用户和多入站 | :heavy_check_mark: |
| 高级流量路由配置界面 | :heavy_check_mark: |
| 用户、流量和系统状态 | :heavy_check_mark: |
| 订阅链接（link/json/clash 及订阅信息） | :heavy_check_mark: |
| 深色和浅色主题 | :heavy_check_mark: |
| API 接口 | :heavy_check_mark: |

## 支持的平台

| 平台 | 架构 | 状态 |
|------|------|------|
| Linux | amd64, arm64, armv7, armv6, armv5, 386, s390x | ✅ 支持 |
| Windows | amd64, 386, arm64 | ✅ 支持 |
| macOS | amd64, arm64 | 🚧 实验性支持 |

## 界面截图

![主界面](https://github.com/alireza0/s-ui-frontend/raw/main/media/main.png)

[查看其他界面截图](https://github.com/alireza0/s-ui-frontend/blob/main/screenshots.md)

## 文档

完整文档位于 [Wiki](https://github.com/bryet/s-ui/wiki)：

| 页面 | 内容 |
|------|----------|
| [订阅服务](https://github.com/bryet/s-ui/wiki/Subscription-Service) | 订阅 URL、三种订阅格式和响应头 |
| [JSON 订阅模板](https://github.com/bryet/s-ui/wiki/Subscription-JSON-Template) | sing-box 订阅模板的结构和支持的字段 |
| [Clash 订阅模板](https://github.com/bryet/s-ui/wiki/Subscription-Clash-Template) | Clash.Meta 模板、代理组和过滤规则 |
| [API 文档](https://github.com/bryet/s-ui/wiki/API-Documentation) | 使用令牌认证的 REST API（`/apiv2`） |
| [配置对象](https://github.com/bryet/s-ui/wiki/Configuration-Objects) | 通过 API 读写的对象结构 |
| [设置参考](https://github.com/bryet/s-ui/wiki/Settings-Reference) | 面板的各项设置及其默认值 |

## 默认安装信息

- 面板端口：2095
- 面板路径：`/app/`
- 订阅端口：2096
- 订阅路径：`/sub/`
- 用户名和密码：均为 `admin`

## 安装或升级到最新版本

### Linux/macOS

```sh
bash <(curl -Ls https://raw.githubusercontent.com/bryet/s-ui/main/install.sh)
```

#### 安装脚本语言

安装脚本支持与面板相同的六种语言：`en`（安装脚本默认语言）、`fa`、`ru`、`vi`、`zhcn` 和 `zhtw`。可以通过 `SUI_LANG` 环境变量选择语言；未设置时，脚本会参考系统的 `$LANG` 值：

```sh
SUI_LANG=fa bash <(curl -Ls https://raw.githubusercontent.com/bryet/s-ui/main/install.sh)
```

### Alpine Linux

Alpine 使用 `apk` 和 OpenRC，而不是 `apt` 和 systemd。安装脚本会自动识别 Alpine，并配置 OpenRC 服务。由于 Alpine 默认未安装 `bash`，请先安装：

```sh
apk add bash
bash <(curl -Ls https://raw.githubusercontent.com/bryet/s-ui/main/install.sh)
```

使用 OpenRC 管理服务：通过 `rc-service s-ui start|stop|restart` 启动、停止或重启服务，通过 `rc-update add s-ui default` 设置开机自启。

### Windows

1. 从 [GitHub Releases](https://github.com/bryet/s-ui/releases/latest) 下载最新的 Windows 版本。
2. 解压 ZIP 文件。
3. 以管理员身份运行 `install-windows.bat`。
4. 按照安装向导完成安装。

## 安装历史版本

在安装命令末尾指定需要安装的历史版本号。例如，安装 `v1.5.0`：

```sh
VERSION=v1.5.0 && bash <(curl -Ls https://raw.githubusercontent.com/bryet/s-ui/$VERSION/install.sh) $VERSION
```

## 手动安装

### Linux/macOS

1. 根据操作系统和架构，从 [GitHub Releases](https://github.com/bryet/s-ui/releases/latest) 下载最新的 S-UI 版本。
2. **可选：** 下载最新的 [s-ui.sh](https://raw.githubusercontent.com/bryet/s-ui/master/s-ui.sh)。
3. **可选：** 将 `s-ui.sh` 复制到 `/usr/bin/`，并运行 `chmod +x /usr/bin/s-ui`。
4. 将 S-UI 的 tar.gz 压缩包解压到指定目录，并进入该目录。
5. 将 `*.service` 文件复制到 `/etc/systemd/system/`，然后运行 `systemctl daemon-reload`。
6. 运行 `systemctl enable s-ui --now`，设置 S-UI 开机自启并启动服务。
7. 运行 `systemctl enable sing-box --now`，启动 sing-box 服务。

### Windows

1. 在 [GitHub Releases](https://github.com/bryet/s-ui/releases/latest) 中找到最新的 Windows 版本。
2. 下载对应架构的安装包，例如 `s-ui-windows-amd64.zip`。
3. 将 ZIP 文件解压到指定目录。
4. 以管理员身份运行 `install-windows.bat`。
5. 按照安装向导完成安装。
6. 访问面板：<http://localhost:2095/app>。

## 卸载 S-UI

### systemd

```sh
sudo -i

systemctl disable s-ui  --now

rm -f /etc/systemd/system/sing-box.service
systemctl daemon-reload

rm -fr /usr/local/s-ui
rm /usr/bin/s-ui
```

### Alpine (OpenRC)

```sh
rc-service s-ui stop
rc-update del s-ui default
rm -f /etc/init.d/s-ui

rm -fr /usr/local/s-ui
rm /usr/bin/s-ui
```

## 使用 Docker 安装

<details>
   <summary>点击查看详情</summary>

### 使用方法

**第一步：安装 Docker**

```shell
curl -fsSL https://get.docker.com | sh
```

**第二步：安装 S-UI**

使用 Docker Compose：

```shell
mkdir s-ui && cd s-ui
wget -q https://raw.githubusercontent.com/bryet/s-ui/master/docker-compose.yml
docker compose up -d
```

使用 Docker 命令：

```shell
mkdir s-ui && cd s-ui
docker run -itd \
    -p 2095:2095 -p 2096:2096 -p 443:443 -p 80:80 \
    -v $PWD/db/:/app/db/ \
    -v $PWD/cert/:/root/cert/ \
    --name s-ui --restart=unless-stopped \
    alireza7/s-ui:latest
```

自行构建镜像：

```shell
git clone https://github.com/bryet/s-ui
git submodule update --init --recursive
docker build -t s-ui .
```

</details>

## 手动运行与开发

<details>
   <summary>点击查看详情</summary>

### 构建并运行完整项目

```shell
./runSUI.sh
```

### 克隆仓库

```shell
# 克隆仓库
git clone https://github.com/bryet/s-ui
# 克隆子模块
git submodule update --init --recursive
```

### 前端

前端代码请参阅 [s-ui-frontend](https://github.com/bryet/s-ui-frontend)。

### 后端

> 构建后端前，请先完成前端构建。

构建后端：

```shell
# 删除旧的前端构建文件
rm -fr web/html/*
# 复制新的前端构建文件
cp -R frontend/dist/ web/html/
# 构建后端
go build -o sui main.go
```

在仓库根目录运行后端：

```shell
./sui
```

</details>

## 支持的语言

- 英语
- 波斯语
- 越南语
- 简体中文（前端默认语言）
- 繁体中文
- 俄语

## 功能说明

- 支持的协议：
  - 通用协议：Mixed、SOCKS、HTTP、HTTPS、Direct、Redirect、TProxy
  - V2Ray 相关协议：VLESS、VMess、Trojan、Shadowsocks
  - 其他协议：ShadowTLS、Hysteria、Hysteria2、Naive、TUIC
- 支持 XTLS 协议。
- 提供高级流量路由配置界面，支持 PROXY Protocol、外部代理、透明代理、SSL 证书和端口配置。
- 提供高级入站和出站配置界面。
- 支持设置用户流量上限和到期时间。
- 展示在线用户、入站和出站的流量统计，并监控系统状态。
- 提供订阅服务，支持添加外部链接和订阅。
- 支持通过 HTTPS 安全访问面板和订阅服务，需要自行提供域名和 SSL 证书。
- 支持深色和浅色主题。

## 环境变量

<details>
  <summary>点击查看详情</summary>

### 使用方法

| 变量 | 类型 | 默认值 |
| -------------- | :--------------------------------------------: | :------------ |
| SUI_LOG_LEVEL  | `"debug"` \| `"info"` \| `"warn"` \| `"error"` | `"info"`      |
| SUI_DEBUG      |                   `boolean`                    | `false`       |
| SUI_BIN_FOLDER |                    `string`                    | `"bin"`       |
| SUI_DB_FOLDER  |                    `string`                    | `"db"`        |
| SINGBOX_API    |                    `string`                    | -             |

</details>

## SSL 证书

<details>
  <summary>点击查看详情</summary>

### Certbot

```bash
snap install core; snap refresh core
snap install --classic certbot
ln -s /snap/bin/certbot /usr/bin/certbot

certbot certonly --standalone --register-unsafely-without-email --non-interactive --agree-tos -d <Your Domain Name>
```

</details>

## 第三方项目

以下是社区围绕 S-UI 开发的项目，它们不隶属于 S-UI，也不由 S-UI 维护，请自行判断是否使用：

- [itning/reset-s-ui-traffic](https://github.com/itning/reset-s-ui-traffic)：定期重置所有用户的流量。
- [zqh2333/s-ui-traffic-reset](https://github.com/zqh2333/s-ui-traffic-reset)：流量重置工具。
- [Sownix21/SUI-Bot](https://github.com/Sownix21/SUI-Bot)：Telegram 机器人。
- [Android 应用](https://github.com/Sownix21/SUI-Node)：多面板管理客户端。

> 如果你正在基于 S-UI 开发 Telegram 机器人、监控或自动化工具等项目，欢迎提交 Issue 或 PR，将项目收录到此处。

## Star 历史

<a href="https://www.star-history.com/?repos=bryet%2Fs-ui&type=date&releases=&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=bryet/s-ui&type=date&theme=dark&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=bryet/s-ui&type=date&legend=bottom-right" />
   <img alt="Star 历史趋势图" src="https://api.star-history.com/chart?repos=bryet/s-ui&type=date&legend=bottom-right" />
 </picture>
</a>
