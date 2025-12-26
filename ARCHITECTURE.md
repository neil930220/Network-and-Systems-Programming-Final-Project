# Bank Vault 项目架构图

本文档提供 Bank Vault 系统的完整架构图和组件说明。

## 系统整体架构

```mermaid
graph TB
    subgraph "客户端层 (Clients)"
        CLI[vault_cli<br/>ncurses TUI<br/>交互式界面]
        LOAD[vault_client<br/>Load Generator<br/>多线程压测工具]
    end
    
    subgraph "网络层 (Network)"
        TCP[TCP Socket<br/>Port 7777]
    end
    
    subgraph "服务器层 (Server)"
        MASTER[Master Process<br/>进程管理<br/>信号处理<br/>共享内存初始化]
        W1[Worker 1<br/>epoll事件循环]
        W2[Worker 2<br/>epoll事件循环]
        WN[Worker N<br/>epoll事件循环]
        
        MASTER -->|fork| W1
        MASTER -->|fork| W2
        MASTER -->|fork| WN
    end
    
    subgraph "共享内存层 (Shared Memory)"
        SHM[POSIX Shared Memory<br/>/dev/shm/vault_shm]
        ACCOUNTS[账户数据<br/>MAX_ACCOUNTS=10000<br/>每账户: mutex + balance_cents]
        COUNTERS[全局计数器<br/>total_requests<br/>total_errors<br/>active_connections<br/>shutdown_flag<br/>next_session_id]
        
        SHM --> ACCOUNTS
        SHM --> COUNTERS
    end
    
    subgraph "协议层 (Protocol Library)"
        PROTO[libproto/protocol.c<br/>编码/解码<br/>CRC32校验<br/>XOR加密<br/>时间戳验证]
    end
    
    subgraph "工具库 (Utility Libraries)"
        LOGGER[libutil/logger.c<br/>结构化日志<br/>级别: debug/info/warn/error/audit]
        SHMLIB[libshm/vault_shm.c<br/>共享内存管理<br/>初始化/清理]
    end
    
    CLI -->|TCP连接| TCP
    LOAD -->|TCP连接| TCP
    TCP -->|accept| W1
    TCP -->|accept| W2
    TCP -->|accept| WN
    
    W1 -->|读写| SHM
    W2 -->|读写| SHM
    WN -->|读写| SHM
    
    W1 --> PROTO
    W2 --> PROTO
    WN --> PROTO
    CLI --> PROTO
    LOAD --> PROTO
    
    W1 --> LOGGER
    W2 --> LOGGER
    WN --> LOGGER
    MASTER --> LOGGER
    
    MASTER --> SHMLIB
    W1 --> SHMLIB
    W2 --> SHMLIB
    WN --> SHMLIB
```

## 服务器内部架构

```mermaid
graph TB
    subgraph "Master Process"
        INIT[初始化阶段]
        SIGNAL[信号处理<br/>SIGINT/SIGTERM]
        FORK[Fork Workers]
        SHUTDOWN[优雅关闭<br/>设置shutdown_flag<br/>等待workers退出]
        
        INIT --> FORK
        SIGNAL --> SHUTDOWN
    end
    
    subgraph "Worker Process (每个Worker)"
        EPOLL[epoll_create1<br/>创建epoll实例]
        ACCEPT[accept新连接<br/>创建session_t]
        READ[读取数据<br/>累积到read_buf]
        PARSE[解析封包<br/>长度前缀切包<br/>proto_decode]
        VALIDATE[验证阶段]
        PROCESS[处理请求]
        WRITE[发送响应]
        
        EPOLL -->|epoll_wait| ACCEPT
        ACCEPT -->|EPOLLIN事件| READ
        READ --> PARSE
        PARSE --> VALIDATE
        VALIDATE --> PROCESS
        PROCESS --> WRITE
    end
    
    subgraph "请求验证流程"
        RATE[Rate Limiting<br/>Token Bucket<br/>50 req/sec]
        TS[Timestamp验证<br/>±30秒窗口]
        AUTH[认证检查<br/>未登录仅允许<br/>LOGIN/PING]
        DISPATCH[分发到操作处理器]
        
        RATE --> TS
        TS --> AUTH
        AUTH --> DISPATCH
    end
    
    subgraph "业务操作处理器"
        LOGIN_H[handle_login<br/>生成session_id<br/>derive session_key]
        BAL_H[handle_balance<br/>锁账户mutex<br/>读取余额]
        DEP_H[handle_deposit<br/>锁账户mutex<br/>增加余额]
        WIT_H[handle_withdraw<br/>锁账户mutex<br/>减少余额<br/>检查余额充足]
        TRA_H[handle_transfer<br/>锁两个账户<br/>固定顺序避免死锁<br/>转账操作]
        PING_H[handle_ping<br/>心跳响应]
        
        DISPATCH --> LOGIN_H
        DISPATCH --> BAL_H
        DISPATCH --> DEP_H
        DISPATCH --> WIT_H
        DISPATCH --> TRA_H
        DISPATCH --> PING_H
    end
    
    subgraph "Session管理"
        SESS_CREATE[创建session_t<br/>初始化rate_limiter<br/>设置非阻塞socket]
        SESS_UPDATE[更新last_seen<br/>累计request_count]
        SESS_CLEANUP[清理session<br/>关闭socket<br/>释放缓冲区]
        IDLE_CHECK[空闲超时检查<br/>60秒未活动断开]
        
        ACCEPT --> SESS_CREATE
        PROCESS --> SESS_UPDATE
        IDLE_CHECK --> SESS_CLEANUP
    end
    
    VALIDATE --> RATE
    LOGIN_H --> SHM
    BAL_H --> SHM
    DEP_H --> SHM
    WIT_H --> SHM
    TRA_H --> SHM
```

## 协议层架构

```mermaid
graph LR
    subgraph "Frame抽象层"
        FRAME[frame_t结构<br/>flags/opcode/seq<br/>timestamp_ms/body/body_len]
    end
    
    subgraph "编码流程 (proto_encode)"
        ENCODE1[分配缓冲区<br/>total = HEADER_SIZE + body_len]
        ENCODE2[写入Header<br/>Len/Magic/Ver/Flags<br/>Op/Seq/Timestamp]
        ENCODE3[写入Body]
        ENCODE4[计算CRC32<br/>覆盖整个封包]
        ENCODE5[写入CRC字段<br/>offset 22]
        
        ENCODE1 --> ENCODE2
        ENCODE2 --> ENCODE3
        ENCODE3 --> ENCODE4
        ENCODE4 --> ENCODE5
    end
    
    subgraph "解码流程 (proto_decode)"
        DECODE1[读取长度字段<br/>验证pkt_len == len]
        DECODE2[验证Magic<br/>0xC0DE]
        DECODE3[验证Version<br/>1]
        DECODE4[提取CRC<br/>保存并清零]
        DECODE5[重新计算CRC<br/>与接收值比较]
        DECODE6[解析字段<br/>flags/opcode/seq/timestamp]
        DECODE7[提取Body]
        
        DECODE1 --> DECODE2
        DECODE2 --> DECODE3
        DECODE3 --> DECODE4
        DECODE4 --> DECODE5
        DECODE5 --> DECODE6
        DECODE6 --> DECODE7
    end
    
    subgraph "安全特性"
        CRC[CRC32完整性校验<br/>检测数据损坏/篡改]
        XOR[XOR加密/解密<br/>session_key派生<br/>username + session_id]
        TS_VALID[时间戳验证<br/>防重放攻击<br/>±30秒窗口]
        KEY_DERIVE[密钥派生<br/>proto_derive_key<br/>CRC32(username+session_id)]
        
        KEY_DERIVE --> XOR
    end
    
    FRAME --> ENCODE1
    DECODE7 --> FRAME
    
    ENCODE4 --> CRC
    DECODE5 --> CRC
    
    XOR --> ENCODE3
    XOR --> DECODE7
    
    TS_VALID --> DECODE6
```

## 共享内存架构

```mermaid
graph TB
    subgraph "POSIX Shared Memory"
        SHM_NAME["/vault_shm<br/>/dev/shm/vault_shm"]
    end
    
    subgraph "vault_shm_t结构"
        GLOBAL_LOCK[global_lock<br/>pthread_mutex_t<br/>PTHREAD_PROCESS_SHARED<br/>PTHREAD_MUTEX_ROBUST]
        
        GLOBAL_COUNTERS[全局计数器区]
        TOTAL_REQ[total_requests<br/>uint64_t]
        TOTAL_ERR[total_errors<br/>uint64_t]
        ACTIVE_CONN[active_connections<br/>uint32_t]
        SHUTDOWN_FLAG[shutdown_flag<br/>uint32_t]
        NEXT_SESSION[next_session_id<br/>uint32_t<br/>单调递增]
        
        GLOBAL_COUNTERS --> TOTAL_REQ
        GLOBAL_COUNTERS --> TOTAL_ERR
        GLOBAL_COUNTERS --> ACTIVE_CONN
        GLOBAL_COUNTERS --> SHUTDOWN_FLAG
        GLOBAL_COUNTERS --> NEXT_SESSION
    end
    
    subgraph "账户数组 (MAX_ACCOUNTS=10000)"
        ACCT_ARRAY[account_t数组]
        
        ACCT0[account_t[0]<br/>lock: mutex<br/>balance_cents: 100000<br/>初始$1000.00]
        ACCT1[account_t[1]<br/>lock: mutex<br/>balance_cents: 100000]
        ACCT_N[account_t[N]<br/>lock: mutex<br/>balance_cents: 100000]
        
        ACCT_ARRAY --> ACCT0
        ACCT_ARRAY --> ACCT1
        ACCT_ARRAY --> ACCT_N
    end
    
    subgraph "互斥锁保护策略"
        SINGLE[单账户操作<br/>Balance/Deposit/Withdraw<br/>锁对应账户mutex]
        DOUBLE[双账户操作<br/>Transfer<br/>按ID顺序加锁<br/>避免死锁]
        GLOBAL_OPS[全局操作<br/>更新计数器<br/>获取session_id<br/>锁global_lock]
    end
    
    SHM_NAME --> GLOBAL_LOCK
    SHM_NAME --> GLOBAL_COUNTERS
    SHM_NAME --> ACCT_ARRAY
    
    GLOBAL_LOCK --> GLOBAL_OPS
    ACCT0 --> SINGLE
    ACCT1 --> SINGLE
    ACCT_N --> SINGLE
    ACCT0 --> DOUBLE
    ACCT1 --> DOUBLE
    ACCT_N --> DOUBLE
```

## 数据流图

```mermaid
sequenceDiagram
    participant Client as 客户端<br/>(CLI/LOAD)
    participant Network as TCP Socket
    participant Worker as Worker Process
    participant Protocol as Protocol Layer
    participant Session as Session Manager
    participant Handler as 业务处理器
    participant SHM as Shared Memory
    
    Client->>Network: 1. 建立TCP连接
    Network->>Worker: 2. accept连接
    Worker->>Session: 3. 创建session_t
    Worker->>Network: 4. 注册epoll事件
    
    Client->>Network: 5. 发送请求封包
    Network->>Worker: 6. EPOLLIN事件触发
    Worker->>Worker: 7. read数据到read_buf
    
    Worker->>Protocol: 8. 解析长度前缀
    Worker->>Protocol: 9. proto_decode验证
    Protocol-->>Worker: 10. 返回frame_t
    
    alt 封包带FLAG_ENCRYPTED且已登录
        Worker->>Protocol: 11. XOR解密body
    end
    
    Worker->>Session: 12. 检查rate limit
    Worker->>Protocol: 13. 验证timestamp
    Worker->>Session: 14. 检查认证状态
    
    Worker->>Handler: 15. 分发到操作处理器
    
    alt 需要访问账户
        Handler->>SHM: 16. 锁账户mutex
        Handler->>SHM: 17. 读写balance_cents
        Handler->>SHM: 18. 解锁mutex
    end
    
    Handler->>SHM: 19. 更新全局计数器
    Handler-->>Worker: 20. 返回响应frame_t
    
    Worker->>Protocol: 21. proto_encode编码
    Protocol-->>Worker: 22. 返回wire buffer
    
    Worker->>Network: 23. write发送响应
    Network->>Client: 24. 接收响应封包
    
    Client->>Protocol: 25. proto_decode解析
    Protocol-->>Client: 26. 返回frame_t
    Client->>Client: 27. 处理响应结果
```

## 客户端架构

```mermaid
graph TB
    subgraph "vault_cli (ncurses TUI)"
        CLI_INIT[初始化ncurses<br/>设置终端大小<br/>80x24最小]
        CLI_UI[UI界面<br/>菜单导航<br/>UP/DOWN/数字键]
        CLI_CONN[建立TCP连接<br/>--host --port]
        CLI_LOGIN[登录操作<br/>输入username<br/>接收session_id<br/>derive session_key]
        CLI_OPS[业务操作<br/>Balance/Deposit<br/>Withdraw/Transfer]
        CLI_HIST[历史记录<br/>显示操作历史<br/>延迟统计]
        CLI_SEND[send_recv函数<br/>encode → write<br/>read → decode]
        
        CLI_INIT --> CLI_UI
        CLI_UI --> CLI_CONN
        CLI_CONN --> CLI_LOGIN
        CLI_LOGIN --> CLI_OPS
        CLI_OPS --> CLI_HIST
        CLI_OPS --> CLI_SEND
    end
    
    subgraph "vault_client (Load Generator)"
        LOAD_ARGS[解析参数<br/>--threads --ops<br/>--mix操作比例]
        LOAD_BARRIER[pthread_barrier<br/>同步所有线程起跑]
        LOAD_WORKER[Worker线程<br/>每个线程独立连接]
        LOAD_CONN[连接服务器<br/>connect_to_server]
        LOAD_LOGIN[执行登录<br/>do_login]
        LOAD_MIX[操作混合<br/>按比例随机选择<br/>Balance/Deposit<br/>Withdraw/Transfer]
        LOAD_STATS[统计收集<br/>延迟百分位数<br/>吞吐量]
        
        LOAD_ARGS --> LOAD_BARRIER
        LOAD_BARRIER --> LOAD_WORKER
        LOAD_WORKER --> LOAD_CONN
        LOAD_CONN --> LOAD_LOGIN
        LOAD_LOGIN --> LOAD_MIX
        LOAD_MIX --> LOAD_STATS
    end
    
    subgraph "通用协议层"
        PROTO_ENCODE[proto_encode<br/>构建封包]
        PROTO_DECODE[proto_decode<br/>解析封包]
        PROTO_KEY[proto_derive_key<br/>派生session_key]
        
        CLI_SEND --> PROTO_ENCODE
        CLI_SEND --> PROTO_DECODE
        CLI_LOGIN --> PROTO_KEY
        LOAD_MIX --> PROTO_ENCODE
        LOAD_MIX --> PROTO_DECODE
        LOAD_LOGIN --> PROTO_KEY
    end
```

## 测试架构

```mermaid
graph TB
    subgraph "单元测试"
        UNIT_PROTO[test_protocol.c<br/>CRC32测试<br/>XOR加密测试<br/>密钥派生测试<br/>时间戳验证测试<br/>编码/解码测试]
    end
    
    subgraph "集成测试脚本"
        TEST_RUNNER[run_all_tests.sh<br/>测试入口<br/>清理环境<br/>顺序执行]
        
        TEST_FAIL[test_failures.sh<br/>失败处理测试<br/>乱码封包<br/>截断封包<br/>错误magic<br/>超大length<br/>多次malformed<br/>连接洪水]
        
        TEST_SHUTDOWN[test_shutdown.sh<br/>关闭测试<br/>SIGINT处理<br/>SIGTERM处理<br/>共享内存清理]
        
        TEST_CONCURRENCY[test_concurrency.sh<br/>并发测试<br/>多客户端压测<br/>操作混合<br/>数据一致性]
        
        TEST_SECURITY[test_security.sh<br/>安全测试<br/>bad magic<br/>bad CRC<br/>oversize<br/>truncate<br/>malformed threshold<br/>rate limiting<br/>随机二进制数据]
    end
    
    TEST_RUNNER --> UNIT_PROTO
    TEST_RUNNER --> TEST_FAIL
    TEST_RUNNER --> TEST_SHUTDOWN
    TEST_RUNNER --> TEST_CONCURRENCY
    TEST_RUNNER --> TEST_SECURITY
```

## 组件依赖关系

```mermaid
graph TD
    subgraph "可执行文件"
        SERVER_BIN[vault_server]
        CLI_BIN[vault_cli]
        CLIENT_BIN[vault_client]
        TEST_BIN[test_protocol]
    end
    
    subgraph "源代码"
        SERVER_SRC[server/vault_server.c]
        CLI_SRC[client/vault_cli.c]
        CLIENT_SRC[client/vault_client.c]
        TEST_SRC[tests/test_protocol.c]
    end
    
    subgraph "库文件"
        PROTO_OBJ[libproto/protocol.o]
        SHM_OBJ[libshm/vault_shm.o]
        UTIL_OBJ[libutil/logger.o]
    end
    
    subgraph "头文件"
        PROTO_H[include/protocol.h]
        COMMON_H[include/common.h]
        SHM_H[include/vault_shm.h]
        LOGGER_H[include/logger.h]
    end
    
    subgraph "外部库"
        PTHREAD[libpthread<br/>多线程支持]
        RT[librt<br/>POSIX共享内存]
        NCURSES[libncurses<br/>TUI界面]
    end
    
    SERVER_SRC --> PROTO_OBJ
    SERVER_SRC --> SHM_OBJ
    SERVER_SRC --> UTIL_OBJ
    SERVER_SRC --> PROTO_H
    SERVER_SRC --> COMMON_H
    SERVER_SRC --> SHM_H
    SERVER_SRC --> LOGGER_H
    
    CLI_SRC --> PROTO_OBJ
    CLI_SRC --> PROTO_H
    CLI_SRC --> COMMON_H
    CLI_SRC --> NCURSES
    
    CLIENT_SRC --> PROTO_OBJ
    CLIENT_SRC --> PROTO_H
    CLIENT_SRC --> COMMON_H
    
    TEST_SRC --> PROTO_OBJ
    TEST_SRC --> PROTO_H
    TEST_SRC --> COMMON_H
    
    PROTO_OBJ --> PROTO_H
    PROTO_OBJ --> COMMON_H
    
    SHM_OBJ --> SHM_H
    SHM_OBJ --> COMMON_H
    
    UTIL_OBJ --> LOGGER_H
    
    SERVER_BIN --> SERVER_SRC
    SERVER_BIN --> PTHREAD
    SERVER_BIN --> RT
    
    CLI_BIN --> CLI_SRC
    CLI_BIN --> NCURSES
    
    CLIENT_BIN --> CLIENT_SRC
    CLIENT_BIN --> PTHREAD
    
    TEST_BIN --> TEST_SRC
```

## 关键设计决策

### 1. 多进程架构
- **Master-Worker模式**: Master负责初始化和信号处理，Workers处理实际请求
- **进程隔离**: 每个Worker独立进程，提高稳定性
- **共享内存**: 使用POSIX shared memory实现进程间状态共享

### 2. 事件驱动I/O
- **epoll**: Linux高效I/O多路复用机制
- **非阻塞Socket**: 避免阻塞整个Worker进程
- **边缘触发模式**: EPOLLET提高性能

### 3. 并发控制
- **Process-shared Mutex**: 跨进程互斥锁保护共享数据
- **固定锁顺序**: Transfer操作按账户ID顺序加锁，避免死锁
- **Robust Mutex**: 处理进程异常终止情况

### 4. 安全机制
- **CRC32校验**: 检测数据完整性（非加密学安全）
- **时间戳窗口**: ±30秒防重放攻击
- **Rate Limiting**: Token bucket算法限制请求速率
- **XOR加密**: 可选body加密（教育用途）

### 5. 协议设计
- **长度前缀**: 便于流式解析
- **Magic Number**: 快速识别协议封包
- **版本字段**: 支持未来协议升级
- **序列号**: 支持请求/响应匹配（当前未完全利用）

## 性能特性

- **高并发**: 每个Worker支持最多1024个并发连接
- **低延迟**: epoll边缘触发模式减少系统调用
- **可扩展**: 通过增加Worker数量横向扩展
- **资源隔离**: 进程级隔离，单个Worker崩溃不影响其他

## 限制与注意事项

1. **平台依赖**: 需要Linux/WSL（依赖fork/epoll/shm_open）
2. **加密非安全**: XOR + CRC32仅用于教学，非生产级安全
3. **写路径简化**: 未完整实现backpressure和write buffering
4. **单机限制**: 共享内存仅支持单机部署

---

*本文档基于 PROJECT_DOC.md 和源代码分析生成*

