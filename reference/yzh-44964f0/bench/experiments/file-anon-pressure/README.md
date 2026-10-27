# 文件页与匿名内存竞争下的观测开销

一个进程内有 1,000 个文件线程和 1,000 个匿名内存线程，共享地址空间与 mmap_lock。文件线程反复扫描约 4 GB 文件映射；内存线程访问链表并逐步增长分配，配置目标约 3 GB。进程限额为 4 GiB 内存、最多 4 核 CPU，禁止 swap。文件页回收与再次缺页形成持续压力。

负载改自 ClickHouse 文章 [A Case of the Vanishing CPU](https://clickhouse.com/blog/a-case-of-the-vanishing-cpu-a-linux-kernel-debugging-story) 中使用的 [serxa/stress_memcg](https://github.com/serxa/stress_memcg)，来源提交为 `0de0a1abdf5beb280dabdd729f044954a6431777`。原源码和 Apache 2.0 许可证见 [upstream](../../../workload/file-anon-pressure/upstream/)，改动见 [workload.diff](../../../workload/file-anon-pressure/workload.diff)。

## 怎么测

每次重新建立临时 cgroup 和私有文件，等全部 2,000 个线程准备好后再计时。无观测、有观测各运行约 60 秒，共 3 轮配对，每轮两者的先后顺序随机。两边使用相同负载代码、固定随机种子及相同用户态工作量计数。

观测配置是一整套锁与回收诊断：

| 接入 | 记录内容 |
|---|---|
| mmap_lock 的 start / acquire_returned / released 三个 tracepoint | 读写次数、状态、等待与持有时间；持有超过 100 ms 时在结束事件取栈并上报 |
| vmscan 的 memcg_reclaim_begin / end、lru_shrink_inactive / active 四个 tracepoint | 回收时间、扫描和回收页数、回收时是否持锁 |
| 每 CPU 49 Hz 的 perf_event | 目标进程的用户态／内核态采样次数、内核栈及持锁情况 |

这套代码在同线程、同 mm 已有写持有状态时，用没有对应读 START 的读 ACQUIRED 推断写降为读，不另挂 downgrade_write。它与 observer/ 当前独立程序的挂点和采集配置不同，测得的是上述整套诊断的成本。

主指标是文件逻辑读取 GiB/s、链表百万节点访问/s，以及同轮有观测相对无观测的吞吐损失：`(1 − 有观测吞吐 / 无观测吞吐) × 100%`。逻辑读取包含反复扫描，不等于磁盘 I/O。CPU 时间分别记录负载 cgroup、独立观测进程和控制进程；采样中断的 CPU 未必全部计入负载，因此不能只用负载 CPU 差解释开销。

文件生成、映射、初始链表准备、线程创建、探针加载和最终导出均在正式计时外。匿名线程保留原程序后续迭代和 30 秒等待逻辑；这是一份加入准备屏障与工作量计数的性能对照版本。

历史汇总见[测试报告](../../../docs/REPORT.html)。当前负载与命令见 [workload](../../../workload/README.md) 和 [bench](../../../bench/README.md)。
