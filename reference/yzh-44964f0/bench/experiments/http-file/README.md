# 常驻 HTTP 文件校验

32 客户端持久连接；每请求建立 4 MiB 文件映射、计算 SHA-256、解除映射。四种 mmap_lock 接入均只采集计数与必要配对。

## 请求与计时窗口

服务提前启动 32 个工作线程，32 个客户端提前建立持久连接并预热。请求 `/checksum/<id>` 选择一个 4 MiB 文件：服务每次新建只读 mmap，直接从映射计算 SHA-256，关闭映射与文件，再返回 64 个十六进制字符加换行；客户端逐次校验。

发布批次每臂固定 26,496 个请求，4 个文件轮转，基线墙钟约 30 秒。四种接入各七组配对。CPU 合计服务、客户端和控制程序的全部线程，独立观测程序另列。只采集计数和必要配对，没有状态、栈、timer 或用户态超时轮询。

该 mmap 路径会写转读降级。普通/raw 同时接入 start_locking、acquire_returned、released，再补 kprobe/downgrade_write；fentry 方案使用 fentry/downgrade_write，kprobe 方案使用 kprobe/downgrade_write。降级新增读 ACQUIRED，不新增直接读 START；逐轮核对读 START－失败＋降级＝读成功获取＝读释放。

## 结果

每臂 26,496 个请求；每方式 7 组，共 28 组成对比较。

[总报告](../../../docs/REPORT.html) · [测量方法](../../../docs/measurement.md)

新负载与命令见 [workload](../../../workload/README.md) · [bench](../../../bench/README.md)。本目录说明历史实验的负载与测量口径。
