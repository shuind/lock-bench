# zlib 编译

固定 zlib 1.3.1；每次清理产物后完整 make -j3，统计编译进程树 CPU 和墙钟。主要观测 mmap_lock 写侧，保留 cgroup 零命中对照。

## 编译与计时窗口

固定 zlib 1.3.1，配置为静态库，每次清理产物后执行 `make -j3 ARFLAGS=rcD 'RANLIB=ranlib -D' all`。源文件缓存保持温热。CPU 汇总 make 及已等待回收的编译子进程树用户态和内核态 CPU；并行时 CPU 可以大于墙钟。

清理、编译产物一致性检查和 zlib 自检在任务计时之外。确定性归档选项避免 libz.a 的时间戳导致假失败。本负载未触发目标 cgroup 写锁，所以三种 cgroup 零命中配置只保留作对照。

## 结果

14 种配置，各 7 组，共 98 组成对比较。

[总报告](../../../docs/REPORT.html) · [测量方法](../../../docs/measurement.md)

新负载与命令见 [workload](../../../workload/README.md) · [bench](../../../bench/README.md)。本目录说明历史实验的负载与测量口径。
