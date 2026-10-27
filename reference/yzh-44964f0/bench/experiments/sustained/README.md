# 大量 fork 与 cgroup 迁移

4 个线程并发 fork；混合负载另由 1 个线程执行 4N 次 cgroup 迁移。比较 fork 间接探针、cgroup fentry/kprobe、contention；另保存固定响应 HTTP 对照。

## 负载与观测范围

大量 fork 由 4 个线程合计完成 N 次 fork、子进程退出与 waitpid。间接探针挂 cgroup_can_fork 与 cgroup_post_fork 的入口，围住相关阶段，不能当作精确读锁等待或持有时间。

混合负载同时做 N 次 fork 和 4N 次整个线程组 cgroup 迁移，两组之间交替。fentry/kprobe 分别观察 percpu_down_write 的入口和返回、percpu_up_write 的入口，按测试 TGID 和 cgroup_threadgroup_rwsem 地址过滤。读侧 inline 持有者仍有盲区。

contention 观察 lock:contention_begin/end 的获取过程。该内核的 percpu 写侧每次获取都会发事件，不能将每个命中解释成真的阻塞；end 不是释放锁。

发布数据各七组配对。CPU 包括测试程序全部线程及已回收子进程，观测程序另列。原批次还保留固定响应 HTTP 的低命中对照，这部分在报告中折叠。

## 结果

每配置 7 组，共 56 组成对比较；基线按约 30 秒校准固定工作量。

[总报告](../../../docs/REPORT.html) · [测量方法](../../../docs/measurement.md)

新负载与命令见 [workload](../../../workload/README.md) · [bench](../../../bench/README.md)。本目录说明历史实验的负载与测量口径。
