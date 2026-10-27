# workload

observer 开发期间使用的实验负载，用于触发锁操作、缺页、资源压力等场景。实现负载准备、工作量计数和执行协议，供 bench 调用或单独运行。

## 构建与独立运行

从仓库根目录执行：

```bash
python3 lockbench.py workload list
python3 lockbench.py workload build --workload all
python3 lockbench.py workload run --workload mmap --duration 30 --concurrency 4
python3 lockbench.py workload run --workload http-file --duration 30 --concurrency 32
sudo python3 lockbench.py workload run --workload memory-pressure
```

独立运行输出 READY 与 RESULT 两行 JSON。bench 调用同一入口，通过私有控制通道发送 GO / FINISH；正式结果先冻结，之后才退出和清理。

当前 HTTP 服务由负载程序直接启动为子进程，并继承其 cgroup；历史 HTTP 批次使用 systemd-run，运行与 CPU 口径见[批次说明](../bench/experiments/http/README.md)。

## 负载

| workload | 正式工作 | 默认关键参数 |
|---|---|---|
| mmap | 反复建立／解除一页匿名映射 | 1 线程，30 秒 |
| mprotect | 已有匿名映射在只读／可写之间切换 | 每线程 16 MiB，1 线程，30 秒；一次操作含两次 mprotect |
| read-maps | 完整读取 /proc/self/maps | 1 线程，30 秒 |
| fault | 丢弃并重新触碰匿名页 | 16 MiB／线程，30 秒 |
| fork | fork、子进程退出、wait | 4 线程，30 秒 |
| cgroup-migrate | 进程在两个私有 cgroup 叶子之间迁移 | 1 线程，30 秒，需要 sudo |
| fork-migrate | 多线程 fork 与最后一个线程持续迁移 | 共 5 线程，30 秒，需要 sudo；分别报告 forks 与 migrations |
| mmap-contention | 同一地址空间内一个 mprotect 写线程与 maps 读线程竞争 | 64 MiB，3 线程，30 秒 |
| memory-pressure | 固定文件映射扫描，暖身后每页读取 8 字节并校验 | 文件 256 MiB、匿名 16 MiB、4 线程、15 遍、内存＋swap 上限 64 MiB |
| http | 新服务启动、4 次 GET /payload、POST /shutdown、退出 | 12 次生命周期，并发 1；每响应 32 KiB |
| http-file | 常驻服务每请求 mmap 文件、SHA-256、munmap、返回校验值 | 32 个持久连接，4 个 4 MiB 文件，30 秒 |
| zlib | 复制本地源码、配置后完成一次干净编译 | --project 必填，--concurrency 为 make -j |
| actrail | 复制本地源码，干净编译 ctl 及全部依赖 | --project 必填，独立 CARGO_TARGET_DIR，强制构建 Java agent；--concurrency 为 jobs |
| file-anon-pressure | 文件扫描与匿名链表访问／增长相互竞争 | 1,000＋1,000 线程、4 GiB 文件、3 GiB 匿名目标、4 GiB 限额、4 核配额，30 秒 |

`--operations` 对 native 负载、HTTP 生命周期／请求设置固定工作量，优先于 duration；memory-pressure 中表示遍数。编译始终完成一次构建；file-anon-pressure 始终按 duration 运行。file-mib、anon-mib、concurrency 等参数只在表中适用的负载生效。

native 与 HTTP 的 operations 是全部工作线程合计的操作数，不是每线程次数。fork-migrate 的固定操作数平均分配给所有线程，计数同时包含 fork 和迁移；按时长运行时分别记录实际完成量，不强制两者比例。memory-pressure 始终按遍数运行，operations=0 时仍扫描 15 遍。

memory-pressure 和 file-anon-pressure 默认申请内存限额，因此需要 sudo；限额同时禁用 swap。MiB 参数使用 1,048,576 字节。file-anon-pressure 的原历史批次使用十进制 4 GB／3 GB，当前 CLI 的默认配置与历史配置有差异，实验实际参数随结果保存。

短跑检查示例：

```bash
python3 lockbench.py workload run --workload fork --operations 100 --concurrency 4
python3 lockbench.py workload run --workload http-file --operations 64 --concurrency 4 --file-mib 1
python3 lockbench.py workload run --workload memory-pressure --file-mib 8 --anon-mib 1 \
  --operations 2 --concurrency 2 --memory-limit-mib 0
python3 lockbench.py workload run --workload zlib --project /path/to/zlib --concurrency 4
python3 lockbench.py workload run --workload actrail --project /path/to/AcTrail --concurrency 4 --run-timeout 3600
```

## 实现

native/ops.c 实现系统调用负载；memory-pressure/memory_scan.c 实现固定映射扫描；http_service.py 实现 HTTP 负载；drivers.py 适配各负载的准备、计时和结束。

file-anon-pressure 保留上游 [serxa/stress_memcg](https://github.com/serxa/stress_memcg) 原源码与 Apache 2.0 许可证；workload.diff 展示准备屏障、固定种子和工作量计数的改动。

构建输出位于各原生负载的 .build/，临时文件位于 --workdir 或 bench 的该次运行目录，大文件结束后删除。

编译负载复制源码到独立构建目录，这是其准备步骤。AcTrail 使用 cargo --offline，需提前缓存依赖并安装项目所需的 JDK／构建工具；避免把网络下载混入编译计时。
