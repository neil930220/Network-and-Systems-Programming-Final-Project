# Bank Vault — Project Architecture (Mermaid)

本檔案提供「整個專案」的架構圖（可直接在 GitHub/Markdown 預覽 Mermaid）。

---

## 1) 全系統總覽（Components + Dependencies）

```mermaid
flowchart LR
  %% ===== External Users =====
  U1([User])
  U2([Load Tester])

  %% ===== Binaries =====
  subgraph BIN[Build Artifacts and Binaries]
    VS["vault_server"]
    VC["vault_client - load generator"]
    VCLI["vault_cli - interactive ncurses TUI"]
    TP["test_protocol"]
  end

  %% ===== Libraries =====
  subgraph LIB[Shared Libraries]
    P["libproto - protocol encode/decode, CRC32, XOR, timestamp"]
    S["libshm - POSIX shm init, robust mutex"]
    L["libutil - structured logger"]
    H["include headers"]
  end

  %% ===== Server internals / OS =====
  subgraph OS[OS Facilities]
    TCP[(TCP Socket)]
    EP[epoll]
    SHM[(POSIX Shared Memory)]
    PM[pthread mutex]
    SIG[Signals]
  end

  %% ===== Tests =====
  subgraph T[Integration Tests]
    R[run_all_tests.sh]
    F[test_failures.sh]
    C[test_concurrency.sh]
    SE[test_security.sh]
    SD[test_shutdown.sh]
  end

  %% ===== Flows =====
  U1 -->|interact| VCLI
  U2 -->|generate traffic| VC
  VCLI -->|Binary Protocol over TCP| TCP --> VS
  VC -->|Binary Protocol over TCP| TCP

  VS --> EP
  VS --> SIG
  VS --> SHM --> PM

  VS --- P
  VS --- S
  VS --- L
  VC --- P
  VCLI --- P
  TP --- P

  P --- H
  S --- H
  L --- H

  R --> TP
  R --> F
  R --> SD
  R --> C
  R --> SE
  F -->|blackbox| VS
  SD -->|signal/cleanup| VS
  C -->|stress| VC
  SE -->|fuzz/bad packets| VS
```

---

## 2) Server 架構（Master + Workers + Shared State）

```mermaid
flowchart TB
  subgraph MASTER[Master Process]
    A["Parse args"]
    B["Init shared memory"]
    C["Create listen socket"]
    D["fork workers"]
    E["Signal handler"]
    F["Set shutdown_flag"]
    G["kill and waitpid workers"]
  end

  subgraph WORKERS[Worker Processes]
    W1[epoll_wait loop]
    W2[accept new connections]
    W3["per-connection session_t"]
    W4["read and process buffer"]
    W5["proto_decode and CRC check"]
    W6["process_request with auth"]
    W7["handle business ops"]
    W8["proto_encode and write response"]
    W9[idle timeout and stats]
  end

  SHM[(POSIX shared memory)]
  ACCT[(accounts with mutex)]
  CNT[(global counters)]

  A --> B --> C --> D --> W1
  E --> F --> G

  SHM --> ACCT
  SHM --> CNT

  W6 <--> SHM
  W7 <--> ACCT
  W2 --> W3 --> W4 --> W5 --> W6 --> W7 --> W8 --> W9 --> W1
```

---

## 3) 單次請求的資料流（Length-Prefixed Frame + CRC + Dispatch）

```mermaid
sequenceDiagram
  autonumber
  participant Client
  participant TCP
  participant Worker
  participant Proto
  participant Shm

  Client->>Proto: proto_encode frame
  Proto-->>Client: wire buffer
  Client->>TCP: write buffer
  TCP->>Worker: EPOLLIN and read

  Worker->>Worker: process read buffer
  Worker->>Proto: proto_decode and check CRC
  alt FLAG_ENCRYPTED
    Worker->>Proto: proto_xor_crypt body
  end
  Worker->>Worker: process_request with rate limit
  Worker->>Shm: lock and update accounts
  Worker->>Proto: proto_encode response
  Worker->>TCP: write response
  TCP-->>Client: response bytes
  Client->>Proto: proto_decode response
  Proto-->>Client: frame with status
```

---

## 4) Source Tree（模組責任摘要）

```mermaid
mindmap
  root((Bank Vault Project))
    server
      vault_server.c
        master fork workers
        epoll accept and read
        request dispatch
    client
      vault_cli.c
        ncurses TUI
        login balance deposit withdraw transfer
      vault_client.c
        multi-thread load generator
        mixed ops and latency stats
    include
      common.h
      protocol.h
      vault_shm.h
      logger.h
    libproto
      protocol.c
        encode and decode
        CRC32
        XOR hooks and key derivation
        timestamp helpers
    libshm
      vault_shm.c
        shm_open and mmap
        PTHREAD_PROCESS_SHARED mutex
        init balances and counters
    libutil
      logger.c
        structured logging
    tests
      test_protocol.c
      run_all_tests.sh
      test_failures.sh
      test_shutdown.sh
      test_concurrency.sh
      test_security.sh
```


