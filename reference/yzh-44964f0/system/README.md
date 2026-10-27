# system

独立的整机系统指标采集器，从 `/proc` 读取 CPU、内存、系统负载和 PSI。可单独运行，由公共会话层与锁采集器组合，也供 bench 实验复用。

## 运行

从仓库根目录执行，需要 Linux 和 Python 3.9+：

默认持续采样，按 `Ctrl+C` 停止并输出最终 JSON。以下示例用 `--duration 60` 限时运行一分钟：

```bash
python3 lockbench.py system run --duration 60 --system-interval-ms 1000 \
  --system-output system.jsonl >system.json 2>system.log
```

默认每秒采样一次，开始与结束时各补一份边界数据。日志中的 `SYSTEM` 行实时显示指标，最终 JSON 写到 stdout；`--system-output` 写入本次完整时间序列，已有同名文件会覆盖。无需 BPF、采集器二进制或 sudo。

每行运行日志使用北京时间，精确到毫秒、不带时区标识，格式为 `2026-10-20 11:22:14.512 SYSTEM ...`，不受服务器时区配置影响。SYSTEM 与读取失败提示由该样本的 wall_time_ns 转换显示；原始时间戳保持不变，elapsed_s 和采样间隔使用 monotonic_ns。

组合观测由外层命令启动：

```bash
sudo python3 lockbench.py run --target mmap --scheme tracepoint --observe on \
  --collect stack --timeout poll --duration 60 --system-output system.jsonl \
  >session.json 2>session.log
```

组合结果中的 `collectors.locks` 和 `collectors.system` 分别保存两套采集结果。`--system off` 从组合会话中去掉系统采集器；`observer run` 始终只运行锁采集器。

## 字段

| 字段 | 内容与口径 |
|---|---|
| samples[].cpu | 在线逻辑 CPU 数、累计计数和相邻采样的利用率；busy＝100－idle－iowait，iowait、steal 等分项另列，guest 不重复计入 |
| samples[].memory | 总量、可用、空闲、缓存、缓冲、swap；used＝MemTotal－MemAvailable，容量单位为字节 |
| samples[].load | 1、5、15 分钟负载，以及采样时可运行／总任务数 |
| samples[].psi | CPU 的 some，内存与 I/O 的 some/full；10、60、300 秒平均百分比、累计停顿微秒、相邻采样区间的停顿比例 |
| samples[].monotonic_ns | 与锁事件对应的单调时钟；wall_time_ns 为实时时钟 |
| cpu_window | 起止 CPU 计数计算的整个采样窗口利用率 |
| sampling_cpu_ns | 采样操作的 CPU 时间，包含首末采样、解析和输出 |
| availability / source_errors | 最后一个样本中各指标是否可用，以及读取失败原因；中途异常见各样本 errors |
| errors | 采样线程或 JSONL 写入等采集过程异常；读取指标失败记录在各样本中 |

首个样本的 CPU 利用率与区间 PSI 为 null；CPU 计数没有增长或发生回退时，区间利用率也为 null。缺少接口、权限不足或内容异常时，对应指标为 null，并记录原因。

最终 JSON 保留最近 3,600 次采样，以 samples_total、samples_retained、samples_truncated 标明总量与截断情况。JSONL 每次采样立即写入并刷新，保存全部记录。

两轮开启／关闭观测的结果可交给独立的 [analysis](../analysis/README.md) 生成对照页面；系统采集器不参与离线统计或页面生成。

系统采样在 Python 进程的后台线程中执行，独立模块不代表独立进程。bench 的 controller_cpu_ns 已包含正式窗口内的采样线程 CPU；sampling_cpu_ns 另含首末采样，不能与 controller_cpu_ns 直接相加。系统与锁采集分别启停，不提供严格同时的原子快照。

若内核设置了 `CONFIG_PSI_DEFAULT_DISABLED=y`，需要在启动参数中加入 `psi=1` 并重启后才能提供 PSI，见[内核配置说明](https://github.com/torvalds/linux/blob/v6.6/init/Kconfig)。[PSI](https://docs.kernel.org/accounting/psi.html) 表示资源压力下的任务停顿，不能当作 CPU 利用率。

## 代码

metrics.py 负责读取、解析、周期采样和容量控制；api.py 实现公共采集器接口；cli.py 提供独立命令。采集器不依赖 observer、workload 或 bench。
