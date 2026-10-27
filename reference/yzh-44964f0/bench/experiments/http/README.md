# HTTP 完整服务流程

每次测量完成 10 次服务启动、4 次 GET 和关闭的完整流程。观测 cgroup 写锁、mmap_lock 写侧或外层函数，支持五档采集配置。

本页记录历史 systemd 服务批次。当前 workload/http 直接启动子进程，默认 12 次生命周期；其 cgroup 与 CPU 计量方式见 [workload](../../../workload/README.md) 和 [bench](../../../bench/README.md)。

## 一次服务流程

1. 控制程序调用 systemd-run，启动一个新的 Python HTTP 服务，systemd 将其放入对应的 cgroup。
2. 服务监听 127.0.0.1 的空闲端口并写出 PID、端口和 cgroup；控制程序等待就绪并查询 systemd 验证身份。
3. 控制程序顺序执行 4 个 GET /payload；每个响应固定 32 KiB，读取完整内容并校验 SHA-256。
4. 发送一个 POST /shutdown；服务响应后停止监听并正常退出。
5. 控制程序确认退出、读取服务 CPU 统计并停止服务单元，然后开始下一次新服务。

一次测量连续做 10 次流程，共 40 次数据请求和 10 次关闭请求。7 轮中，每轮无探针跑 10 次、探针跑 10 次，所以每配置有 140 次正式流程。独立验证的 2 次流程不进入正式统计。

墙钟从放行控制程序到其退出，包含 Python 启动、systemd 管理命令、就绪等待、请求、响应校验及流程中的记录工作。它衡量服务完整生命周期，不能当作稳态吞吐或单次请求延迟。

CPU 是控制程序及其已回收子进程的 wait4 用户态/内核态 CPU，加上 PID 1 的继承 task CPU clock，覆盖计量窗口内新启动的服务等子进程。服务自身的 cgroup CPU 仅用于核对，不重复相加；同期其它 PID 1 工作可能影响小差值。

## 结果

16 种配置，各 7 组，共 112 组成对比较。

[总报告](../../../docs/REPORT.html) · [测量方法](../../../docs/measurement.md)

新负载与命令见 [workload](../../../workload/README.md) · [bench](../../../bench/README.md)。本目录说明历史实验的负载与测量口径。
