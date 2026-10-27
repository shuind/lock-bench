# ebpf-lock-bench

Linux eBPF 锁观测工具。observer 观测整机的 mmap_lock、cgroup 写锁和 fork 相关阶段，记录计数、等待与持有状态、入口内核栈及超时事件。system 独立采样 CPU、内存、系统负载和 PSI，外层会话可组合两套采集器。

[observer 使用说明](observer/README.md) · [系统指标](system/README.md) · [完整 CLI 参数](docs/cli.md) · [代码架构](docs/architecture.md)

## 观测能力

| 对象 | 观测内容 | 接入方式 |
|---|---|---|
| mmap_lock | 读写锁获取、释放、写转读降级 | fentry/fexit、kprobe/kretprobe、普通/raw tracepoint |
| cgroup_threadgroup_rwsem | 写锁获取与持有，或争用获取阶段 | fentry/fexit、kprobe/kretprobe、contention 事件 |
| fork | cgroup_can_fork 到 cgroup_post_fork 的代码阶段 | kprobe/kretprobe |

每种“对象 × 接入方式”有独立的源码和产物，也可组合观测多个对象。具体挂点、覆盖边界和 timer 支持见 [observer](observer/README.md)。

## 预编译运行包

[下载 ARM64 运行包](releases/lockbench-linux-arm64.tar)：包含八套采集器、`.bpf.o`、Python 入口和 libbpf/libelf 等运行库。适用于 ARM64 Linux、glibc 2.34+、Python 3.9+；内核须提供 BTF 和对应 BPF 功能。八套程序已在 glibc 2.34 动态加载器下验证 `.o` 检查和无观测运行。

```bash
tar -xf lockbench-linux-arm64.tar
cd lockbench-linux-arm64
sudo python3 lockbench.py run --target all --observe on >result.json 2>observer.log
```

5.10 厂商内核若支持 fentry，可显式选择 mmap/cgroup 的 fentry；fork 仍使用 kprobe：

```bash
sudo python3 lockbench.py run --target all --scheme fentry --observe on >result.json 2>observer.log
```

默认轮询使用不含 timer helper 的普通 `.o`；只有 `--timeout timer` 才选择 fentry 的 timer 版 `.o`。主线 5.10 未提供 mmap_lock tracepoint，ARM64 的 fentry 支持也取决于厂商回移；若缺少 fentry，可显式用 `--scheme kprobe`。实际覆盖边界见 [observer](observer/README.md#覆盖范围)。

## 构建

实际环境只取采集器与公共入口：

```bash
git clone --depth 1 --filter=blob:none --sparse https://atomgit.com/qiaodizhong/ebpf-lock-bench.git
cd ebpf-lock-bench
git sparse-checkout set observer system analysis
```

只用锁采集器时，将最后一行改为 `git sparse-checkout set observer`。后续使用 `git pull --ff-only` 更新。

锁采集器构建需要 Linux、Python 3.9+、支持 BPF 的 Clang、libbpf/libelf/zlib 开发文件和内核 BTF。用户态程序自动选择 `gcc`、`cc` 或 `clang` 编译，也可通过环境变量 `CC` 指定；BPF 编译器通过 `CLANG` 指定，默认 `clang`。构建时通过 libbpf 自动导出内核类型头文件，无需安装 bpftool；也可用 `--vmlinux-header /path/to/vmlinux.h` 指定兼容的现成头文件。构建入口支持 ARM64 与 x86-64，已验证环境为 ARM64 / openEuler 24.03 SP3 / Linux 6.6。单独运行 system 只需 Linux 和 Python。

从仓库根目录执行：

```bash
python3 lockbench.py observer build
```

## 观测已有业务

观测默认持续运行，按 `Ctrl+C` 停止并导出最终 JSON；指定 `--duration` 才会自动限时退出。例如同时观测全部对象并采集系统指标：

```bash
sudo python3 lockbench.py run --target all --observe on
```

这条命令默认用普通 tracepoint 观测 mmap、fentry/fexit 观测 cgroup 写侧、kprobe/kretprobe 观测 fork，记录计数、状态和入口内核栈。所有选中对象每 100 ms 轮询一次，操作持续达到 100 ms 时输出 `SLOW` 提示及已保存的入口栈；提示可能晚于阈值，两次扫描之间已经结束的操作可能漏报。fork 提示对应其观测代码阶段，覆盖范围见 [observer](observer/README.md#覆盖范围)。

观测整机 mmap_lock，记录计数、状态和入口栈，每 100 ms 检查一次持续达到 100 ms 的操作，持续 30 秒：

```bash
sudo python3 lockbench.py run --target mmap --scheme tracepoint --observe on \
  --collect stack --timeout poll --duration 30 >result.json 2>observer.log
```

`observer.log` 包含配置、超阈值时的实时提示与已保存入口栈，以及周期系统状态；`result.json` 中的 `collectors.locks` 和 `collectors.system` 分别保存两套结果。没有超阈值提示时，日志不会逐次打印锁操作。超阈值表示慢操作，需要结合等待阶段、持有阶段、调用栈和系统状态分析原因。

运行日志统一使用北京时间，精确到毫秒，不带时区标识，例如 `2026-10-20 11:22:14.512 SYSTEM ...`，不受服务器时区配置影响。elapsed 和等待／持有时长仍使用单调时钟计算。

系统指标默认每秒采样一次。使用 `--system-interval-ms` 调整间隔，`--system-output system.jsonl` 持续保存全部采样；`--system off` 关闭系统指标。字段与采样口径见 [system](system/README.md)。

同时观测 mmap、cgroup 与 fork：

```bash
sudo python3 lockbench.py run --target all --observe on --collect stack \
  --timeout poll --fork-timeout poll --duration 30 >result.json 2>observer.log
```

`--collect count|state|stack` 选择采集内容，`--timeout none|poll|timer` 选择超时检测方式；对象专用参数可覆盖统一设置，例如 `--fork-timeout none` 单独关闭 fork 提示。直接运行单套二进制、查看 `.o` 和完整输出字段见 [observer 使用说明](observer/README.md)。

两个采集器也可单独运行：

```bash
sudo python3 lockbench.py observer run --target mmap --scheme tracepoint --observe on --duration 30
python3 lockbench.py system run --duration 30 --system-output system.jsonl
```

## 对照两轮运行

开启、关闭锁观测各运行一小时，并分别保存系统采样：

```bash
sudo python3 lockbench.py run --target all --observe on --duration 3600 \
  --system-output on-system.jsonl >on.json 2>on.log
sudo python3 lockbench.py run --target all --observe off --duration 3600 \
  --system-output off-system.jsonl >off.json 2>off.log
```

两轮结束后生成对照页，无需 sudo，也可将结果文件带回本机分析：

```bash
python3 lockbench.py compare --on on.json --off off.json \
  --on-system on-system.jsonl --off-system off-system.jsonl --output comparison.html
```

打开 comparison.html，查看指标汇总、时间曲线、慢提示和采集错误。两轮业务流量与工作量应尽量相同；性能判断还需结合业务吞吐和延迟。参数与统计口径见 [离线对照](analysis/README.md)。

## 连续采集

[measure.sh](measure.sh) 只负责采集：默认做 3 轮对照，每轮关闭和开启观测各 30 分钟，共 6 段，总计约 3 小时；轮内先后顺序交替。关闭段只采集系统指标，开启段使用 all/kprobe，业务保持自行运行。

将脚本放在 `lockbench.py` 同目录，后台运行：

```bash
sudo -v
nohup sudo -n bash measure.sh --output night-run >night-run.log 2>&1 &
echo $!
```

`night-run` 须为新目录；每组保留 `on.json`、`off.json`、两份 `.log` 和两份完整系统采样 JSONL，不自动分析或生成 HTML。开始前会短跑检查探针，已有锁观测实例运行时会提示先停止它。用 `tail -f night-run.log` 查看进度，提前停止使用 `sudo kill -TERM PID`。

参数：`--duration` 每段秒数、`--repeats` 组数、`--target` 观测对象、`--scheme` 接入方式、`--threshold-ns` 慢提示阈值（默认 100000000 ns）、`--poll-ms` 轮询间隔（默认 100 ms）、`--output` 新结果目录；也可运行 `bash measure.sh --help`。

例如按 10 ms 阈值、5 ms 轮询做资源对照：

```bash
nohup sudo -n bash measure.sh --threshold-ns 10000000 --poll-ms 5 \
  --output night-10ms >night-10ms.log 2>&1 &
```

预检和正式开启段使用相同阈值与轮询间隔，关闭段仍只采集系统指标。缩短间隔带来的轮询成本也计入对照；此方式检查尚未结束的操作，不能保证捕获所有持续超过 10 ms、但在两次扫描之间结束的操作。

## CPU 开销归因

观测保持运行，在另一终端执行短时诊断：

```bash
sudo python3 diagnose.py --duration 60 --output cpu-diagnosis.json
```

脚本自动发现正在运行的原生采集进程，列出各进程的用户态／内核态 CPU 时间，以及每个 BPF 程序的执行频率、平均执行耗时、CPU 核数和整机 CPU 占比，按 BPF 耗时排序。同时检查程序是否经过 JIT 编译。`--pid PID [PID ...]` 可指定原生 `observer` 进程。

每秒保留完整快照。进程退出、程序关闭或手动中断时，仍导出已有完整区间，标为 `partial` 并注明实际时长和结束原因；尚无完整区间时保存 `error`，不填写 CPU 估计值。只有完成指定时长才返回退出码 0，提前结束返回 1。终端末尾显示 JSON 的绝对路径。

只需 Python 标准库。BPF 运行统计通过内核接口临时开启，诊断结束或中断时关闭本次统计引用；开启期间会增加 BPF 计时成本。厂商内核若不支持，输出会明确标为不可用，仍保留进程 CPU 测量。诊断不停止现有观测。

进程 CPU 与 BPF 耗时可能重叠，不能直接相加。BPF 耗时包含程序及同步 helper，但没有覆盖全部探针分发、kretprobe 返回处理和间接影响。先用它定位最贵的进程、程序；取栈与状态维护各自的增量，再通过保持业务相近、分别关闭这些功能的对照判断。

## 代码结构

| 位置 | 内容 |
|---|---|
| [observer/](observer/README.md) | 锁采集器源码、原生运行时和各方案的构建入口 |
| [system/](system/README.md) | 独立的系统指标采集器 |
| [analysis/](analysis/README.md) | 离线对比开启、关闭观测的结果并生成 HTML |
| [session.py](session.py) | 公共接口与会话编排 |
| [workload/](workload/README.md) | 开发实验负载，用于触发锁、缺页和资源压力等场景 |
| [bench/](bench/README.md) | 调用采集器与负载，运行对照实验、分析结果和生成报告 |

## 开发实验

workload 和 bench 用于开发期间验证观测覆盖、比较采集成本。负载与实验命令分别见 [workload](workload/README.md) 和 [bench](bench/README.md)。

[测量方法](docs/measurement.md) · [实验记录](bench/experiments/README.md) · [测试报告](docs/REPORT.html)
