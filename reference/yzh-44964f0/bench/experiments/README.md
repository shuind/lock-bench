# 实验与历史批次

各目录记录历史实验的负载与测量范围，汇总见[测试报告](../../docs/REPORT.html)。新实验由 bench 调用当前 observer 与 workload，生成的结果保存在本机对应负载的 results/run-*。

| 实验 | 内容 |
|---|---|
| [actrail](actrail/README.md) | AcTrail ctl 编译 |
| [http](http/README.md) | HTTP 完整服务流程 |
| [http-concurrency](http-concurrency/README.md) | HTTP 服务启动并发 |
| [http-file](http-file/README.md) | 常驻 HTTP 文件校验 |
| [http-read-comparison](http-read-comparison/README.md) | HTTP 读侧接入对照 |
| [http-scaling](http-scaling/README.md) | HTTP 流程数量对照 |
| [memory-pressure](memory-pressure/README.md) | 缺页压力四种接入对照 |
| [micro/cgroup-fork](micro/cgroup-fork/README.md) | cgroup 与 fork 微测试 |
| [micro/consistency](micro/consistency/README.md) | 历史一致性复测 |
| [micro/mmap](micro/mmap/README.md) | mmap＋munmap 微测试 |
| [state-collection](state-collection/README.md) | 内存压力下的采集成本 |
| [sustained](sustained/README.md) | 大量 fork 与 cgroup 迁移 |
| [file-anon-pressure](file-anon-pressure/README.md) | 文件页与匿名内存竞争下的观测开销 |
| [zlib](zlib/README.md) | zlib 编译 |
