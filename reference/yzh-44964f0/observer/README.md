# observer

在整台主机上观测 mmap_lock、cgroup 写锁和 fork 相关阶段。按“观测对象 × 接入方式”分别实现和构建，每套都有自己的 `probe.bpf.c`、可执行程序和 `.o`。

实际环境的精简检出与构建命令见[仓库首页](../README.md#构建)。

[序列图与 map 操作](../docs/lock-flow.html) 按方案展示入口、获取、释放、降级及超时提示的处理步骤。

## 目录与产物

| 方案目录 | 接入点 | timer¹ |
|---|---|---|
| mmap/fentry/ | down_read / down_write 各变体的 fentry/fexit，up_read、up_write、downgrade_write 的 fentry | 支持 |
| mmap/kprobe/ | 对应函数的 kprobe/kretprobe | 不支持 |
| mmap/tracepoint/ | mmap_lock_start_locking、mmap_lock_acquire_returned、mmap_lock_released；另挂 downgrade_write kprobe | 不支持 |
| mmap/raw/ | 同三个 mmap_lock raw tracepoint；另挂 downgrade_write kprobe | 不支持 |
| cgroup/fentry/ | percpu_down_write 的 fentry/fexit、percpu_up_write 的 fentry | 支持 |
| cgroup/kprobe/ | percpu_down_write 的 kprobe/kretprobe、percpu_up_write 的 kprobe | 不支持 |
| cgroup/contention/ | lock:contention_begin、lock:contention_end | 不支持 |
| fork/kprobe/ | cgroup_can_fork 入口及失败返回、cgroup_post_fork 入口 | 不支持 |

¹ timer 能力按已验证的 Linux 6.6 内核列出，原因见 [测量方法](../docs/measurement.md)。mmap kprobe 另有 sched_process_exit 挂点清理返回参数；锁记录的退出清理由用户态统一处理。

每个方案目录包含：

```text
probe.bpf.c           该方案的全部挂点
backend.c             连接到公共运行时的方案描述
backend.json          外层识别用的名称、能力与程序清单
dist/observer         固定方案的可执行程序
dist/observer.bpf.o   只包含该方案的 BPF 程序与 map
dist/observer.timer.bpf.o  仅 fentry：含 timer 的独立版本
```

fentry 的 `probe.bpf.c` 构建普通版本，`probe.timer.bpf.c` 构建 timer 版本。普通版本不包含 timer map 或 helper；默认轮询加载普通版本，只有 `--timeout timer` 才加载 timer 版本。

`common/` 共用加载、门控、输出、轮询、返回探针管理和状态结构；`mmap/state.bpf.h` 共用 mmap 读写与降级状态处理。公共运行时不根据 CLI 选择探针方案，方案在编译时确定。

已验证环境为 ARM64 / openEuler 24.03 SP3 / Linux 6.6.0-132.0.0.111；运行要求内核 BTF、libbpf/libelf/zlib 运行库和对应挂点。

## 5.10 内核的接入选择

主线 5.10 没有 mmap_lock tracepoint，厂商内核可能回移；ARM64 fentry 的支持也取决于厂商回移，不能只凭内核版本号保证挂点可用。

支持 fentry 的厂商内核可按以下方式观测 mmap/cgroup；fork 仍使用 kprobe。默认的计数、状态、入口栈和用户态轮询使用不含 timer helper 的普通 `.o`：

```bash
sudo python3 lockbench.py run --target all --scheme fentry --observe on >result.json 2>observer.log
```

不支持 fentry 时可显式改用 `--scheme kprobe`。普通方案使用 `bpf_get_current_task` 获取线程地址；记录 ID 按观测程序 `/proc` 的 PID 命名空间解析。仍需内核 BTF、对应函数、BPF 栈采集能力及所选挂点支持；这些调整不等于已经在所有厂商的 5.10 内核上验证通过。加载失败时保留完整 verifier 日志。

## 构建与使用

从仓库根目录执行，需要 Linux、支持 BPF 的 Clang 和 libbpf/libelf/zlib 开发文件。用户态编译器依次寻找 `gcc`、`cc`、`clang`；环境变量 `CC` 可指定其名称或路径，`CLANG` 可指定 BPF 编译器，默认 `clang`。例如只有 Clang 时可执行 `CC=clang python3 lockbench.py observer build`。

构建通过 libbpf 读取 `/sys/kernel/btf/vmlinux`，自动生成 `.build/vmlinux.h`，无需 bpftool。类型导出仅在构建时运行，不加载 BPF，也不需要 sudo。

`observer run` 与原生二进制默认持续运行，按 `Ctrl+C` 停止、卸载并导出最终结果；显式指定 `--duration 30` 才会在 30 秒后退出。

```bash
# 全部八套，或只构建一套
python3 lockbench.py observer build
python3 lockbench.py observer build --target mmap --scheme tracepoint

# 使用已有的内核类型头文件
python3 lockbench.py observer build --vmlinux-header /path/to/vmlinux.h

# 观测已有业务，结果写 stdout，配置与实时超时提示写 stderr
sudo python3 lockbench.py observer run --target mmap --scheme tracepoint --observe on \
  --collect stack --timeout poll --duration 30 >result.json 2>observer.log

# 组合多个独立采集器
sudo python3 lockbench.py observer run --target mmap,cgroup --observe on --collect stack \
  --mmap-scheme tracepoint --mmap-timeout poll --cgroup-timeout timer --duration 30

# 查看这一套 .o 的实际程序、section 和 map，不加载 BPF
python3 lockbench.py observer inspect --target mmap --scheme tracepoint
```

指定的头文件须包含采集器使用的内核类型，并与目标架构和内核类型布局兼容；使用现成头文件不替代运行时对内核 BTF 和对应挂点的要求。

也可直接运行固定方案的产物：

```bash
sudo observer/mmap/tracepoint/dist/observer run --observe on --collect stack \
  --timeout poll --duration 30 >result.json 2>observer.log
observer/mmap/tracepoint/dist/observer inspect
```

固定方案程序接受 `--observe`、`--collect`、`--timeout`、`--duration`、`--threshold-ns`、`--poll-ms`、`--rw`、`--object` 和 `--help`，默认值与统一 CLI 相同；`inspect` 只接受 `--object`。`--object` 默认指向程序旁的 `observer.bpf.o`，timer 模式自动选择 `observer.timer.bpf.o`，必须属于同一套方案。直接部署时保留程序与需要的 `.o` 及 libbpf/libelf/zlib 运行库，Python 只用于外层入口。

系统指标由独立的 [system](../system/README.md) 采集器提供；外层 `python3 lockbench.py run` 可将两者组合。

统一入口默认选择 mmap/tracepoint、cgroup/fentry、fork/kprobe。`--scheme` 显式设置所选 mmap/cgroup 对象的方法，`--mmap-scheme`、`--cgroup-scheme` 可分别覆盖；fork 固定使用 fork/kprobe。所有对象继承统一 timeout，可用对象专用参数覆盖。完整参数见 [CLI](../docs/cli.md)。

## 采集与超时

默认 `--collect stack --timeout poll --threshold-ns 100000000 --poll-ms 100`：所有选中对象记录计数、状态和入口内核栈，每 100 ms 检查持续达到 100 ms 的操作并输出 `SLOW` 及已保存的入口栈。`--fork-timeout none` 可单独关闭 fork 提示。仅状态使用 `--collect state`，仅计数使用 `--collect count --timeout none`。

| 参数 | 内容 |
|---|---|
| collect=count | 累计计数和必要配对记录 |
| collect=state | 加上阶段、开始时间和获取成功时间 |
| collect=stack | 加上入口内核栈 |
| timeout=none | 结束时导出，不检测超时 |
| timeout=poll | 用户态按 poll-ms 检查现存状态，达到 threshold-ns 后提示 |
| timeout=timer | BPF timer 到期通知用户态 |

poll/timer 要求 state 或 stack。阈值从 START 计时，包括等待与持有；实时输出的 stage_ms 表示当前阶段持续时间。轮询提示可能晚于阈值，显示已保存的入口栈（仅 stack 模式），不重新采集线程当前栈；两次轮询间已结束的超阈值操作可能漏报。超阈值表示慢操作，不能据此认定死锁。

轮询优先批量读取状态；内核或 map 类型不支持时自动回退逐条读取，批量缓冲不足时也会回退完成本次扫描。两种路径都重新确认慢候选记录，避免把扫描期间已删除或改变阶段的旧值直接上报。主循环同时等待控制消息和 timer 通知，按下次扫描期限唤醒；停止命令或信号可立即打断等待。

启动配置、超时提示、栈行及运行错误均带北京时间前缀，精确到毫秒、不带时区标识，例如 `2026-10-20 11:22:14.512 SLOW ...`，不受服务器时区配置影响。这是日志输出时间；elapsed_ms、stage_ms 仍按事件的单调时钟计算，避免系统校时影响时长。

## 覆盖范围

| 对象与方式 | 整机范围内记录什么 |
|---|---|
| mmap 普通/raw tracepoint | 事件提供 mm，接收读写获取、释放；包括访问其他进程 mm 的事件。降级由额外 kprobe 根据已有写持有记录补齐 |
| mmap fentry/kprobe | 通过 sem == current->mm->mmap_lock 识别当前地址空间的锁，排除其他 rwsem；完成与降级跟随已接纳记录 |
| cgroup fentry/kprobe | 全局 cgroup_threadgroup_rwsem 的写侧获取和释放；inline 读侧持有者有盲区 |
| cgroup contention | 这把锁的争用获取阶段，end 代表获取过程结束 |
| fork kprobe | cgroup_can_fork → cgroup_post_fork 代码阶段；失败返回时清理 |

所有方案不按 PID 筛选，仍需识别所选锁。mmap 函数方案在访问其他 mm、新 mm 尚未装入当前线程等路径存在边界。普通/raw tracepoint 也只覆盖内核实际发出的事件。写锁降级时结束写状态，读写模式下建立读持有状态；仅写模式不继续跟踪读阶段。

`--rw write` 控制接纳范围，不卸载读侧挂点；读侧触发仍有接入与识别成本。`total_*` 是所挂函数／事件的整机触发数，`match_*` 是接纳的目标操作。全局 rwsem 函数还会被其他锁触发，不能与 mmap 专用事件的 total 直接比较。

## 输出与容量

单个对象输出一份 JSON；组合运行输出 `objects.mmap`、`objects.cgroup`、`objects.fork`。主要字段：

| 字段 | 含义 |
|---|---|
| scope | 固定为 host |
| counters | 累计触发、命中、读写、降级及错误次数 |
| entry_stacks | 去重后的入口栈 ID 与最多 32 帧的地址；降级处建立的读状态也会取栈 |
| live_events | 实时显示过的去重超时记录 |
| timeout_events | timer 上报事件 |
| unfinished | 停止时尚未完成的状态 |
| attached | 该次实际挂载的程序名称 |
| state_scan_mode | 实际使用的 batch、scalar，或尚未扫描的 unused；scan_batch_calls、scan_scalar_calls、scan_fallbacks 记录扫描和回退次数 |
| live_dedup_evictions | 慢提示去重缓存的淘汰次数；淘汰后同一操作可能再次提示，不影响锁状态 |
| ring_buffer_bytes | 实际创建的通知缓冲区大小，普通 poll/none 对象为 0 |
| mmap_reaped_records / mmap_cleanup_errors | 用户态回收的 mmap 退出残留记录数，以及清理检查错误数 |
| stack_capacity / stack_warning_emitted | 栈表总容量，以及是否已提示过采集失败 |

正常释放删除对应状态，栈表在会话期间保留。最终 JSON 的栈帧保存地址；实时超时日志从本机 `/proc/kallsyms` 尽力解析函数名，无法解析时保留地址。当前输出不保存每次已完成操作的完整明细或耗时分布。

状态中的 stage=1 表示获取中、stage=2 表示已获取；fork 的 stage=1 表示所选代码阶段，contention 的 stage=1 表示获取过程。mmap 同键重复入口计入 `mm_duplicate` 和 `pair_errors`，原记录保留时间和栈、标记 stage=3，达到阈值后以 conflict 提示观测配对冲突，不将其当作正常等待或持锁；线程退出后回收。`mm_return_old`、`mm_release_old` 表示完成事件的锁不同于当时 current mm，包含跨 mm 和 exec 切换，不能当作丢失次数。

每套产物独立拥有 map。mmap 使用一张 `mm_records`，键为锁地址、线程地址、线程创建时间和读写类型，值为配对与状态记录；整张表最多 8192 项。计数档只填身份和配对标志，时间为 0、栈 ID 为 -1；state/stack 档在同一记录里增加诊断信息，value 的编译结构大小一致。cgroup/fork 的配对和状态表仍分别保存，各最多 8192 项。各产品栈表合计 8192 项。timer 专用对象另有 timer map 和 4 MiB ring buffer；普通 poll/none 对象不包含这两类 map。容量和采集失败通过 state_errors、pair_errors、stack_errors、timer_errors、ring_dropped 等字段体现。

mmap 正常释放或获取失败时，BPF 立即删除对应完整键。用户态每 5 秒及停止时扫描记录，校验 `/proc/TID/stat` 的线程状态和创建时间，回收已退出或身份已变化的线程残留；慢候选提示前也会核实。创建时间属于键的一部分，线程地址复用不会覆盖旧键。读取失败则保守保留并增加 `mmap_cleanup_errors`。此维护在 count/state/stack 和 none/poll/timer 各档都启用；主机观测应使用主机的 `/proc` 视图。

每个挂点只查一次本 CPU 的计数结构，再更新多个字段；导出时汇总所有 CPU。mmap 的六个总计数由对应读写计数相加得出，JSON 字段及统计含义保持一致。栈采集碰撞或主表存储不足时会尝试溢出表；最终失败增加 stack_errors，其中存储／分配不足另计 stack_capacity_errors。stack 模式每 5 秒检查一次错误，停止时也检查，首次发现后输出 STACK_WARNING。已有栈 ID 和内容保持不变，不静默淘汰被引用的栈。

最终 JSON 最多列出 64 个入口栈、64 个未完成状态、256 条 timer 事件和 256 条实时事件，超出以 truncated 字段标识。停止时关闭新事件接纳，最多等待 500 ms 让已接纳操作完成；整机仍在工作时 unfinished 可以非空。

## 外层接口

[公共采集器接口](../session.py) 定义 prepare、start、cpu_ns、stop、result、close。会话与实验层负责准备、启动、读取 CPU、停止、取结果和清理，其中 cpu_ns 可多次调用。[api.py](api.py) 根据能力清单装配单个或组合采集器，[native.py](native.py) 实现进程、控制通道和结果导出。增加方案时，在独立目录实现探针与描述并登记能力，实验计时流程继续使用这个接口。
