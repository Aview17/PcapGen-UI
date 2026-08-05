# PcapGen-UI

简易报文构造器 —— 基于 PyQt5 + Scapy 的 pcap 报文生成工具，支持 HTTP / TCP / UDP 协议的交互式流量包构造。

## 功能特性

- **多协议支持**：支持 HTTP、TCP、UDP 三种协议的报文生成（UDP 暂未实现）
- **完整的 TCP 流模拟**：自动构造 TCP 三次握手、数据交互、四次挥手报文
- **MTU 分片**：自动对大 payload 按 MTU 进行 TCP 分段处理
- **HTTP 请求校验**：自动校验请求方法、Host 字段、Content-Length 的正确性，支持自动修正
- **默认模板库**：
  - 请求模板：GET、POST、PHP/JSP/ASP 一句话上传、随机 TCP 请求
  - 响应模板：200/404/500 状态码、/etc/passwd 泄露、命令执行结果、随机 TCP 响应
- **灵活的网络配置**：支持自定义 TCP/UDP 源目 IP 和端口，未填写时自动随机生成
- **真实时间戳模拟**：报文间自动添加随机时间间隔
- **随机 MAC 地址**：每次生成使用全新的随机单播 MAC 地址
- **输出 pcap 文件**：结果保存为标准 `.pcap` 格式，可用 Wireshark 等工具直接打开

## 系统要求

- Python 3.6+
- macOS / Windows / Linux

## 安装与运行

### 1. 克隆项目

```bash
git clone <repo-url>
cd PcapGen-UI
```

### 2. 创建虚拟环境（推荐）

```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# 或 .venv\Scripts\activate  # Windows
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 启动应用

```bash
python run_window.py
```

## 使用说明

1. **选择协议**：在右下角选择 `HTTP 报文生成` 或 `TCP 报文生成`
2. **填写 payload**：
   - HTTP 模式：直接输入原始的 HTTP 请求/响应文本（如用 BurpSuite 抓取的报文）
   - TCP 模式：输入十六进制格式的原始数据（如 `aabbccdd`）
3. **添加默认模板**（可选）：从下拉框选择预置模板，点击"添加默认请求/响应"快速填充
4. **配置四元组**（TCP/UDP 模式下）：填写源目 IP 和端口，留空则自动随机生成
5. **设置输出路径**：选择保存文件夹，默认文件名为 `out.pcap`
6. **点击"生成"**：生成完成后在输出目录查看 `.pcap` 文件

### HTTP 模式说明

HTTP 模式下会自动从请求的 `Host` 字段解析目标 IP 和端口，源 IP 自动生成同 C 段地址。支持以下自动修正：

- `\n` 自动转换为 `\r\n`
- `Content-Length` 与实际 body 长度不一致时自动修正
- POST 请求缺失 `Content-Length` 时自动补全
- GET 请求多余 `Content-Length` 自动清为 0

### TCP 模式说明

TCP 模式下请求/响应内容需填写**十六进制格式**的原始字节数据（不含空格和换行）。例如：

```
474554202f20485454502f312e31
```

## 项目结构

```
PcapGen-UI/
├── run_window.py                # 应用入口
├── MainWindow.py                # 主窗口，绑定 UI 事件与控制器
├── README.md
├── .gitignore
├── favicon.ico
├── ui/
│   └── Main.ui                  # Qt Designer UI 源文件
├── views/
│   └── Main.py                  # UI 编译生成的 Python 代码
├── controllers/
│   ├── __init__.py               # TextLog 日志类
│   ├── GenerateController.py     # 报文生成流程控制
│   ├── OSController.py           # 文件/文件夹操作
│   └── PayloadController.py      # 默认 payload 填充逻辑
├── logic/
│   ├── HTTPPcapGenLogic.py       # HTTP pcap 生成核心逻辑
│   ├── TCPPcapGenLogic.py        # TCP pcap 生成核心逻辑
│   └── UDPPcapGenLogic.py        # UDP pcap 生成（待实现）
├── models/
│   ├── default_communication_filled.py  # 默认请求/响应模板数据
│   └── other_model.py            # 其他常量（版本号等）
├── Tools/
│   ├── NetworkTools.py           # 网络工具函数（IP/端口校验、MAC生成等）
│   └── ProgramTools.py           # 程序内部工具（时间戳调整等）
└── resources/
    └── icons/
        └── main_icon.ico         # 应用图标
```

## 技术架构

项目采用类 MVC 分层架构：

- **views/** —— 视图层：由 Qt Designer 生成，负责 UI 布局
- **controllers/** —— 控制层：接收 UI 事件，协调逻辑层完成报文生成
- **logic/** —— 逻辑层：核心报文构造算法（基于 Scapy）
- **models/** —— 数据层：默认模板数据、常量定义
- **Tools/** —— 工具层：通用网络工具函数和程序内部工具

### 报文生成流程

```
用户输入 payload → 校验合规性 → 获取/生成网络四元组
    → 随机生成 MAC 地址 → 构造三层 IP 包
    → 构造 TCP 三次握手 → 遍历请求/响应对构造数据包（自动分段）
    → 构造 TCP 四次挥手 → 调整时间戳 → 输出 pcap 文件
```

## 待办事项

- [ ] UDP 报文生成逻辑实现
- [ ] 支持导入已有 pcap 文件进行编辑
- [ ] 响应字段合规性校验
- [ ] 更多默认模板

## 许可证

MIT License
