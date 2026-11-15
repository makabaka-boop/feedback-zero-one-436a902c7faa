# 归档 + 主密钥轮换（Python 3 / SQLite / AES-256-GCM）

三个独立进程、两个独立数据库：

| 角色 | 代码 | 进程入口 | 数据 |
|---|---|---|---|
| 密钥服务 | `archive/keyserver.py` | `bin/run.py keyserver` | 自己的 `keys.db`（代数主密钥 + 永久墓碑） |
| 归档 HTTP 服务 | `archive/server.py` | `bin/run.py server` | `archive.db`（索引/包封）+ `data/objects/`（正文密文） |
| 轮换工作进程 | `archive/worker.py` | `bin/run.py worker` | 只共享归档库与目录锁，可随时重启 |

两者之间只通过 HTTP 通信，可延迟、重复、丢应答。归档端磁盘上**没有正文**，
也没有明文数据密钥。

## 启动

```bash
# 1. 密钥端（先起；写出自己的地址）
python3 -I bin/run.py keyserver --db keys/keys.db --port 0 \
        --endpoint-file keys/endpoint.json

# 2. 归档端（读取密钥端地址文件；自动创建空档、上传代号 0、主密钥 0）
python3 -I bin/run.py server --db archive/archive.db --data archive/data \
        --endpoint-file keys/endpoint.json --endpoint-out archive/endpoint.json

# 3. 轮换工作进程（可反复重启；--once 跑一遍就退出）
python3 -I bin/run.py worker --db archive/archive.db --data archive/data \
        --endpoint-file keys/endpoint.json
```

`-I` 会移除脚本目录和当前目录，`bin/run.py` 显式加入仓库根目录，避免数据目录中
被放置的同名模块（如 `json.py`）被导入。

## 接口（归档端）

| 请求 | 语义 | 返回 |
|---|---|---|
| `POST /put {"id","text"}` | 发布不可变归档对象 | `null` |
| `POST /read {"id"}` 或 `GET /read?id=` | 读正文 | 正文字符串 |
| `POST /rotate {"job"}` | 登记/重查轮换 | 目标代号（整数） |
| `POST /status {"job"}` | 查状态 | `{"target":n,"state":"pending"\|"done"}` |

也可用 `python3 -I bin/run.py client --url URL put a 甲` 形式的 CLI。
错误统一为 `{"error":"<参数名>"}`；`id`/`text`/`job` 非法分别为
`{"error":"id"}`、`{"error":"text"}`、`{"error":"job"}`，并**不改变业务状态**。
密钥端不可用返回 503 `{"error":"keystore"}`（同样不改状态）。

密钥端 HTTP（无任何返回主密钥的接口）：

```
GET  /v1/keys/<gen>            -> {gen, exists, tombstoned[, key_id]}
POST /v1/keys/<gen>/create     -> {gen, key_id, created}     幂等
POST /v1/keys/<gen>/wrap       {data_key}  -> {gen, key_id, nonce, wrapped}
POST /v1/keys/<gen>/unwrap     {key_id, nonce, wrapped} -> {gen, data_key}
POST /v1/keys/<gen>/destroy    -> {gen, destroyed, existed}  幂等 + 永久墓碑
```

## 设计与正确性要点

**每个对象**：随机 256-bit 数据密钥 `k` 用 AES-256-GCM 加密 UTF-8 正文（AAD 绑定 id），
`k` 再经密钥端用该代号主密钥包封（AAD 绑定 `gen`+`key_id`）。磁盘只有
`data/objects/<sha256(id)> = magic‖nonce‖密文` 和索引里的包封 `(gen‖key_id‖nonce‖ct)`。
GCM 的 AAD 与 `key_id` 校验共同保证：包封被挪到别的 id 或别的代号下都解不开。

**发布原子性**：先写正文文件（tmp + fsync + rename + 目录 fsync），再在
`BEGIN IMMEDIATE` 事务里插入对象行（含包封、正文长度与 SHA-256）。行可见即发布完成。
`put` 比较同一 id 已存明文决定“同文重试返回 null / 异文 `{"error":"text"}`”，
拒绝不落任何状态。

**迟到上传**：`put` 在跨进程 upload 锁内读取 `uploaded_gen`，并在同一事务中写入；
`rotate` 原子地把 `uploaded_gen` 加一并固定 target。因此迟到的 `put` 只会用**当前**
代号，不会落回已退役代号。

**轮换状态机**（`job` 记录 target / prev_gen / state，target 一经登记永不改变）：

1. `rotate(job)`：旧 job 直接返回原 target；新 job 若有未完成轮换则拒绝（`{"error":"job"}`）；
   否则一个事务内登记 pending、`uploaded_gen += 1`、固定 target。
2. `copy`：worker 逐批把所有 `gen < target` 的对象包封用目标代号重新包封
   （只动包封，正文密文与 `body_sha` 不变），每换一个即事务提交。
3. 确认**没有已发布对象依赖旧代号**后，从新到旧对每个 `gen < target` 执行
   `destroy`（幂等）并 `GET` 复核墓碑。
4. 只有复核通过才把 job 写为 `done`（单独事务）。任何阶段崩溃/重启都幂等续办。

**旧包封读取**：读到的行若引用已销毁代号，密钥端回 410，读取方丢弃缓存包封、
重新取当前包封重试（`read_with_envelope(..., stale)` 即此路径，验收中有覆盖）。

**销毁不可复活**：`destroy` 在同一事务删除密钥行并写墓碑；`create` 对墓碑代号一律 410，
所以迟到的 `create` 无法复活，该代号的 wrap/unwrap 永远被拒。

**串行等价**：upload 锁（`flock` + 线程锁）串行化 `put` 与 `rotate`；worker 锁保证
同时只有一个轮换在迁移。协议中的所有校验（重试/冲突/墓碑/目标代号）天然幂等，
因此丢应答重试与重复请求与单次执行等价。

**重启续办**：所有阶段状态都在 SQLite（WAL + `synchronous=FULL`）里；已确认的正文
（行已提交）在崩溃后仍在；worker 与密钥端崩溃后重启会继续，直到 `done`。

## 测试与验收

```bash
# 111 项进程级验收（独立进程/独立库/真实 HTTP/真实 SIGKILL）
python3 -I tests/acceptance.py

# 22 项单测：后端、密钥端，以及经过“丢应答/重复/延迟”TCP 代理的端到端测试
python3 -I -m unittest discover -s tests -p "test_*.py" -v
```

`tests/acceptance.py` 覆盖的场景：

- **A 基本轮换**：存 `a="甲"` → `rotate("job1")=1` → worker 完成 →
  `read(a)="甲"`、`status={"target":1,"state":"done"}`、密钥端 0 号已销毁且密钥行已删；
  同 id 同文重试 `null`、异文 `{"error":"text"}` 且正文不变；空串、astral 字符、超长 id、
  各类非法类型；归档目录（含 WAL）与密钥目录全盘扫描无正文、无明文密钥。
- **B 迁移暂停**：worker 暂停在迁移中时，新上传与读取照常；迟到上传落在新代号；
  轮换期间再 `rotate` 被拒；完成后旧代号销毁；旧包封读取仍返回正文。
- **C 密钥端在墓碑落盘后、回包前被 SIGKILL**：重启后 0/2 号仍墓碑、`create` 仍 410；
  任务仍 pending；带旧包封的读取透明重取当前包封成功；随后轮换完成。
- **D 密钥端在 create 落盘后、回包前被 SIGKILL**：重启后目标代号密钥存在，轮换完成。
- **E 归档服务在 put 落盘后、回包前被 SIGKILL**：客户端收到传输错误，重启后正文可读，
  同文重试为 no-op，新上传仍用当前代号。
- **F worker 在“旧密钥销毁已确认、done 未写”时被杀**：任务仍 pending，读取正常，
  重启后完成，`done` 出现。
- **G 并发**：10 线程持续上传/读取的同时完成轮换，无错误、无明文落盘。
- **H worker 在迁移中途被杀**：代际部分迁移（新旧并存），读取/上传均正常，重启后完成。

崩溃注入点（`archive/faults.py`，仅测试用环境变量启用）：
`ARCH_KILL_AFTER_{PUT_COMMIT,DESTROY_COMMIT,CREATE_COMMIT,MIGRATE_COMMIT,WORKER_DESTROY}`、
`ARCH_PAUSE_MIGRATION`。

## 已知取舍

- 未完成轮换期间**新** `rotate` 一律拒绝；重查已有 job 始终返回其原 target。
- 密钥端不可达时 `rotate` 仍会登记（target 已固定），worker/后续上传会自动重试建钥；
  轮换保持 pending 直到成功。
- 读操作不只依赖缓存包封，每次读都从索引取当前包封；`read_with_envelope` 仅用于
  演示/测试“持旧包封”的路径。
- 并发上传到同一 id 的胜者由 upload 锁决定；失败方按同文/异文规则返回 `null` 或
  `{"error":"text"}`。
