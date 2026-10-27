# bench

observer 开发期间使用的实验工具。调用独立的锁采集器、系统采集器与 workload，比较采集成本，管理计时、配对、分析和报告。runner 接收采集器工厂，通过统一生命周期接口调用；负载负责工作量与正确性检查。

## 运行

从仓库根目录执行：

```bash
python3 lockbench.py bench build --workload http-file
sudo python3 lockbench.py bench run --workload http-file --target mmap \
  --scheme tracepoint --collect stack --timeout poll --duration 30 --repeats 7
python3 lockbench.py bench report --output docs/REPORT.html
```

`bench build` 构建采集器和所选负载。`bench run` 每轮安排无观测、有观测各一次，顺序由 seed 随机决定；`--observe off` 只运行基线，用于检查负载和测量链路。每轮完成后保存原始记录，全部结束后自动生成统计与 CSV。

## 计时顺序

1. 有权限时创建私有 cgroup，启动负载；其后创建的线程和子进程继承该边界。
2. 负载完成文件、映射、工作线程、连接和预热等准备，通知 READY。
3. 有观测组准备锁采集器，完成加载与挂载，然后打开事件接纳门控。
4. 记录负载 cgroup 与系统起点，按配置启动系统采样，再记录观测／控制进程 CPU 与墙钟起点，发送 GO。
5. 负载冻结工作量并通知 RESULT，保持存活；控制程序记录结束快照。
6. 停止系统与锁采集器，导出结果；通知负载 FINISH，清理进程、临时 cgroup 和大文件。

HTTP 生命周期负载的启动、请求、关闭本来就是正式工作，因此放在 GO 之后。编译负载在 GO 前复制源码与配置，GO 后做一次全新编译；它是固定工作量，不按 duration 截断。

## CPU 范围

使用 sudo 时，通过独立 cgroup 的 cpuacct（v1）或 cpu.stat（v2）记录负载的所有线程和子孙进程。观测进程位于该 cgroup 外，单独用进程 CPU 时钟读取正式窗口内的 CPU。控制程序也单独记录 CPU，加载和最终 JSON 导出不包含在观测进程的这段 CPU 中。

无权限且不请求资源限额时，可运行 `--observe off`：CPU 使用负载报告的自身、已回收子进程与仍存活直接子进程的 CPU，结果中的 cpu_scope 明确标记。这个口径与 cgroup 计量不混合配对。

observer 观测整机，事件次数也是整机数据；工作量计数只属于负载。锁采集略早于 GO 开始，结束后最多等待 500 ms 完成已有记录，最终事件次数与负载计时窗口不严格重合。异步回调和其他进程触发的 BPF 成本未必计入负载 CPU，负载 CPU 差值不能当作整机总成本。

CPU、内存、负载和 PSI 默认每秒采样，基线和观测组使用相同配置。`--system-interval-ms` 调整间隔，`--system off` 关闭；每次运行的 system.jsonl 保存完整序列，measurement.json 中的 system 保留窗口 CPU 与最近 3,600 次采样。采样自身的 CPU 时间包含首末采样，单独记在 system.sampling_cpu_ns。

系统采样线程属于 bench 控制进程，正式窗口内的采样 CPU 已包含在 controller_cpu_ns 中；sampling_cpu_ns 用于单独查看采样成本，不能再直接相加。

## 数据与分析

```text
bench/experiments/<workload>/results/run-*/
  parameters.json           实际参数、实现及观测范围
  raw.jsonl                 每次运行的原始测量
  round-*/
    controller.log          负载适配器输出与异常
    workload.log            原生负载的输出与异常（按负载）
    observer/<target>/
      observer.log          该采集器的配置、超时提示与异常
      observer.json         该采集器的原始输出
    observer.json           单个或组合采集结果
    measurement.json        单次计量与系统快照
    system.jsonl            全部系统指标采样
  summary.json              中位数、MAD、MADN、范围与配对明细
  rounds.csv                逐轮比较
  completed.json            全部轮次完成标记
```

CPU 增量、墙钟增量、百分比和吞吐损失先逐对计算，再分别取中位数。固定时长负载看同等时间完成了多少工作；固定工作量负载重点看 CPU 与墙钟增量。负差值或负损失不能证明观测免费。

mmap_lock 的读、写入口分别保留触发次数、命中次数与命中率，写入逐轮 CSV、汇总 JSON 和 HTML。命中率先逐轮计算再取中位数；fentry/kprobe 的触发包含其它 rwsem，命中为成功纳入跟踪的 mmap_lock 入口，不含写锁降级。缺字段不按零计算。

重新分析或更新报告：

```bash
python3 lockbench.py bench analyze --input /path/to/run-directory
python3 lockbench.py bench check --input /path/to/run-directory
python3 lockbench.py bench report --input /path/to/run-directory --output docs/REPORT.html
```

不指定 report 的 input 时，扫描本机统一运行器生成的批次；报告展示新实验汇总，并保留历史结果表格。旧实验的负载、采集实现与 CPU 范围见 [experiments/](experiments/)。

检查报告表格、页内链接与新实验的汇总下载：

```bash
python3 lockbench.py bench check
```

完整参数见 [CLI](../docs/cli.md)。
