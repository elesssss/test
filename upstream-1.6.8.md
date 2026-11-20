# 上游 v1.6.8 选择性合并记录

## 基线和边界

- 本地基线：`c568f46e8b899fe474db0f91f9116d82dec21566`。
- 后端：`alireza0/s-ui` v1.6.7 `3c38b80172d4a6cbfcce9fd224a899d8b126d440` → v1.6.8 `b659142befa4881a889b6c6735b966febc966fd9`。
- 前端：`alireza0/s-ui-frontend` v1.6.7 `f473aeba368de6581cad70412c098ed98370cbcc` → v1.6.8 `461ec847b354d9c98ba80f2c74adc83eee3abade`。
- 对照两个版本间公开 diff，逐段合入普通跟踪目录 `frontend/`，不转换成 gitlink、不导入依赖目录或生成前端产物。
- 此记录是源码合并说明，**不是发布公告或运行验收报告**。未运行 Go/npm 测试、vet、lint、构建、漏洞扫描、服务启动、数据库迁移或真实客户端验收；未安装依赖/编译器、提交、推送或发布。

## 已写入的功能及兼容策略

| 上游主题 | 主要提交 | 本地落点及处理 |
| --- | --- | --- |
| SQLite JSON BLOB | `77a0da8e` | `cmd/migration/1_3.go`、`service/{client,endpoints,inbounds}.go`：JSON 函数的 BLOB 参数显式转 TEXT，包含本地 L2TP 用户选择；入站 ID 使用参数绑定。没有新增数据库列。 |
| 入站开关 | `d4fdd8e0`；前端 `9b45fbb7` | 原有 `Options.enable`、`IsEnabled()`、事务/运行态回滚、前端 `toggle` 已等效，不复制上游 Enable 列或运行态操作。新增 raw/Happ 与 JSON/Clash 读取时过滤，保留持久化链接以便重新启用；只过滤绑定入站对应的 local 分组，不删除同名 external/sub。 |
| 多地址 TLS 与 Host | `7f528484`、`f7f5fc66` | `sub/jsonService.go`、`util/genLink.go`：隔离各地址 TLS map；WS/HTTPUpgrade 在无显式 Host 时回退有效 TLS SNI。保留 remark、去重、mixed、realm 和本地协议逻辑。 |
| Clash WS early data / VLESS encryption | `3d312ddc`、`800dc521` | `sub/clashService.go`、`util/linkToJson.go`：保留字段，外部 VLESS encryption 仅在 Clash 路径保留，不写入普通 sing-box JSON。 |
| Hysteria2 Gecko | `9b3808e9`；前端 `d02a3dc0` | Gecko 类型、密码、packet sizes 配套类型/表单/JSON/Clash 转换；另补 URI 中 `obfs-min-packet-size`、`obfs-max-packet-size` 往返。未填省略，切换 salamander 清理 Gecko 字段。已对照本地 sing-box 1.14.4 schema，未做运行验证；第三方客户端是否读取新增 URI 参数需独立确认。 |
| Snell 多地址入口 | `3b4dccd9`；前端 `dff43331` | 原有后端地址展开增加回归，前端开放 Snell 客户端/多地址设置。L2TP 保持专属界面。 |
| ECH | `8065b49d`；前端 `3235da1c` | PEM/base64/query-name 导入、分享与 Clash；补 VMess 分享再导入。以服务端 ECH 开关为准，兼容 typed/string-interface PEM 数组。前端 public name 仅传给生成接口，非配置字段；校验完整 PEM/base64 后再替换旧配置，错误数组/过期请求不覆盖旧值。六种 locale 配套。 |
| HTTP(S)/SOCKS5/Happ | `d1c2ce92`、`792b2b93`；前端 `f0b0255e` | 显式端口代理 URL 及 socks 别名；拒绝代理路径；external 不发起订阅抓取，sub 才抓取。Happ 过滤 HTTP(S) 代理并规范化 socks5，二维码使用 `happ://add/` 加显式格式 URL；保留 L2TP 凭据、加载时序。 |
| UA 自动选择 | `62c5c46d` | 首个 UA 产品 token：Happ→Happ，Clash 系/Mihomo/Stash→Clash，sing-box/SFA/SFI/SFM/SFT→JSON，其余原始链接。显式 format 优先（空/未知值返回 400）。GET/HEAD 共用选择与 Vary，HEAD 不返回正文、不抓取外部订阅。保留订阅信息和安全文件名 headers。 |
| 内核版本 | `ad1e4e99`；前端 `7b7fcad4` | `sys.coreVersion` 从构建模块信息读取，支持 replace，缺失时为空；前端可选 tooltip，不修改 appVersion 或升级版本比较。 |
| WireGuard 空端口 | 前端 `ee5d4723` | 空值写数字 0、零显示为空，并限制 0–65535；Endpoint 新建随机端口逻辑不变。 |
| RHEL | `d8bf4c9f` | 根据本地中文安装脚本结构添加 RHEL 检测和 DNF 分支；管理脚本两处配套。未修改 fork 下载源/服务单元，不代表实机验证。 |
| go-jose 安全更新 | `19302d16` | `go.mod`/`go.sum`：4.1.4→4.1.6，使用固定上游校验和；未下载/测试新模块。 |
| CI 并行/缓存 | `36fee60e`、`89d2988d` | 新建本地 `test.yml`：独立格式、Go test/race（含嵌套模块）、前端任务和依赖缓存；保留本地 race guards、独立 ICMP/L2TP 流程。修正 release checkout 对普通前端目录的描述，不改变发布触发器。未将新工作流宣称为已通过的发布门禁。 |

## 明确未合入或暂缓

1. **面板 IP 配置允许无 SNI TLS**（`b4b4dbbe`）：权限机制要求对此 TLS 例外单独明确确认；目前 `network/tls.go` 与配套 `middleware/domainValidator.go` 均未修改，不绕过拦截。此项未完成。
2. **其余 Go 依赖刷新**（`1ec386a4`）：gzip/sessions/gopsutil/purego 和 x/* 保留本地版本。没有编译测试时不把整个依赖图变动视为已兼容；需后续单独升级和验证。
3. **前端工具链/库批量升级**（`90416fe1`）：保留 `frontend/package.json` 与 lockfile 原有版本及本地 Node engines，不复制上游 lockfile，也不删除本地测试工具。这些功能补丁不依赖所升级库的新 API；新旧库兼容性仍待构建/测试。
4. **安全政策/OSS Scanner**（`db6f7abf`）：不复制上游维护者邮箱、支持时限承诺和扫描镜像。上游镜像会删除本地前端并克隆移动 main，且测试失败不阻断镜像构建；不适合直接导入本 fork。私密报告渠道和固定源码扫描环境应由维护者确认后另行配置。
5. **上游版本号/子模块指针**（后端 `b659142b`、前端 `461ec847`）：功能目标版本不等同于本 fork 发布号。保留当前 app/package 版本以及 release-build 的注入机制；历史 `.gitmodules` 不变。
6. **上游 core 测试放开 race guard**：不照搬，因为本地策略生命周期与 L2TP 有独立实现和已有 guard；上游测试成功不是本地 race 安全性的证明。

## 源码检查和后续验证

本轮只执行改动 Go 文件的 gofmt、`git diff --check`、manifest/lock 元数据核对、六种 locale 键检查、受保护路径差异检查。新增回归源码覆盖 SQLite TEXT/BLOB/L2TP、多地址 TLS/Host、入站禁用/恢复/外链保留、Snell、Gecko、ECH、外部代理与订阅区分、Clash encryption/early data、Happ/UA/HEAD/Vary、内核版本以及前端表单/二维码。

`deps/veepin/`、`core/`、模型的开关表示、运行态事务/升级恢复和前端 revision store 未改动。新 CI 尚未执行，不能宣称测试通过。

获授权后应：

- 使用 `build-tags.sh` test profile 在根模块跑 vet/相关与完整测试及 race；独立进入 `deps/veepin` 跑协议及 race。继续保留需要隔离命名空间和特权的 L2TP/ICMP 用例，分别验收。
- 在 `frontend/` 干净 `npm ci` 后运行 test/lint/build，再产生嵌入资源（本轮没有 `frontend/dist` / `web/html` 产物）。
- 用隔离旧数据库验证开关、JSON BLOB、回滚与旧配置兼容；验证 UA/格式、Happ/Clash/sing-box 实际导入、ECH/Gecko 客户端支持；真实 iKuai 多拨与容量、RHEL、更新恢复另做实机验收。
