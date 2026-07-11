# MoonTLS-Parser 项目申报书

**项目名称**：MoonTLS-Parser — 安全传输协议嗅探与 JA3 指纹识别库  
**参赛方向**：系统能力与运行时框架 / 工程基础设施 / 安全协议解析  
**仓库地址**：GitHub `https://github.com/yhsrtty/MoonTLS-Parser`；GitLink `https://gitlink.org.cn/yhsrtty/MoonTLS-Parser`

## 一、项目目标

MoonTLS-Parser 面向旁路流量审计、Wasm 网关、轻量代理和安全实验环境，提供纯 MoonBit 的 TLS ClientHello 解析与 JA3 指纹生成能力。项目不解密业务流量，只读取 TLS 握手阶段仍可见的结构化字段，提取 SNI、ALPN、Cipher Suites、Supported Groups、EC Point Formats、Signature Algorithms 等信息，生成可复现的 JA3 字符串和 MD5 摘要，用于客户端分类、灰名单策略、恶意软件通信特征归档和安全教学演示。

## 二、MoonBit 适配价值

TLS 指纹识别通常依赖 Go、Python、Rust 或网络安全平台内置实现。MoonTLS-Parser 将这一类二进制协议解析能力沉淀为 MoonBit 生态库，突出三个价值：一是适合编译到 Wasm，在边缘代理或浏览器侧实验环境中运行；二是类型明确、依赖少，便于安全工具链复用；三是以测试夹具和接口摘要约束行为，为后续 pcap 适配、JA4 扩展、策略引擎和协议教学材料留出清晰接口。

## 三、核心实现范围

当前版本已实现 TLS record 与 ClientHello 长度校验、握手类型识别、分片输入的流式解析、GREASE 值过滤、SNI 与 ALPN 提取、JA3 canonical string 与 digest 生成，并提供 `ClientHelloStream`、`parse_client_hello`、`ClientHello::ja3_string`、`ClientHello::ja3_digest` 等公开 API。项目明确不做 TLS 解密、TCP 重组、证书链验证和完整入侵检测系统；这些能力将作为后续扩展模块，而不是混入首版核心库。

## 四、测试与验收计划

仓库包含手工构造的 ClientHello 测试向量，覆盖 SNI `example.org`、ALPN `h2/http/1.1`、TLS 1.3 Cipher Suites、Supported Groups、Signature Algorithms、JA3 摘要稳定性与流式解析等待逻辑。验收命令为 `moon check --warn-list +73`、`moon test`、`moon info`、`moon run --target js cmd/main`，并提供 `scripts/verify_acceptance.ps1` 统一检查 README、LICENSE、CI、来源说明、源码规模、提交历史和 Mooncakes 可检索状态。

## 五、开源合规与来源说明

项目采用 Apache-2.0 许可证。解析器、测试、文档和演示均为本仓库原创 MoonBit 实现；仅参考 TLS ClientHello 与 JA3 的公开协议行为，不复制第三方解析器代码。MD5 由 `moonbitlang/x/crypto` 提供，仅用于兼容 JA3 指纹格式，不作为安全哈希推荐。仓库已提供 `docs/source-attribution.md` 说明来源、边界和后续维护范围。

## 六、预期成果

完成后交付一个可安装、可测试、可演示、可继续扩展的 MoonBit 安全协议解析库：公开仓库保持 GitHub 与 GitLink 同步，README 给出最小 API 和运行方式，CI 保证基础质量，Mooncakes 发布后供其他 MoonBit 项目直接依赖。后续计划加入更多真实 ClientHello 样本、JA4 完整字段、pcap/hex 输入适配器、规则匹配接口和面向课程实验的可视化示例。
