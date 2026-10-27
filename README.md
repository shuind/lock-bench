# 研究任务：为什么 HTTP 负载中的 mmap_lock 观测回调比 Kbuild 慢

这份材料给独立研究者或自主 agent。请从源码和原始分轮数据独立核对结论，继续解释差距；不要把一个未经验证的优化当作本任务的答案。

## 问题和背景

我们用 eBPF 观测整机的 Linux `mmap_lock`，包括读、写和写锁降级。业务触发加锁时，BPF 程序将锁地址、线程身份和读写类型组成 key，在预分配 HASH map `mm_records` 中插入一条用于配对的记录；加锁返回时更新记录，释放时删除，降级有专门处理。启用完整采集时还保存状态、内核入口栈，并可在用户态轮询慢操作。

用户关心的核心问题是：**为什么同一观测方案下，HTTP 文件校验负载的目标写锁 START 回调比 Linux Kbuild 头文件导出负载慢得多？** 不只解释一个 map helper，也请解释其他分段的差距。这里的“慢”指私有诊断版对目标写锁 START 回调内部的分段耗时，不等同于锁等待时间、单次系统调用总耗时，也不直接等于业务 CPU 增量。

原始 Kbuild 和 HTTP 归因对照都使用普通的插入/删除记录，没有采用后面单独试验的“线程记录复用”优化。内核哈希表使用预分配节点，不应假设每次插入都会调用 `malloc`。

## 已测环境与代码版本

- 服务器：ARM64、4 个逻辑 CPU，openEuler 系列 Linux `6.6.0-132.0.0.111.oe2403sp3.aarch64`；`bpf_stats_enabled=1`。编译器、内核厂商回移、硬件和背景负载都可能影响结果。
- **早期 Kbuild A/B/C 实验**：GitCode 分支作者的采集器 `44964f0`；对应代码在 [reference/yzh-44964f0](reference/yzh-44964f0/)。这版与后面的采集器不同。
- **HTTP–Kbuild 归因实验**：测试元数据记录采集器 `57326bc`；服务器原始源码保存在 [experiments/mmap-cause-20261026/source/observer](experiments/mmap-cause-20261026/source/observer/)，实际分段诊断改写版保存在 [instrumented/observer](experiments/mmap-cause-20261026/instrumented/observer/)。这两份是从测试机取回的源码；原 Git 对象不在当前本地仓库中，提交号来自实验元数据，不能仅凭提交号独立验证源码来源。
- 使用的内核哈希表及跟踪相关源码摘录在 [reference/kernel-6.6](reference/kernel-6.6/)；它是测试内核源码的摘录，不是完整可构建内核。

### 两种负载

1. **Kbuild**：`make -j1 headers_install`。每次清理生成的 `usr/include` 后重新导出，成功产物为 965 个头文件、6,344,974 字节。诊断只统计 `make` 及其子进程的命中，采集器本身仍是整机观测。
2. **HTTP**：常驻 Python 服务、32 个工作线程和 32 个客户端，预热后完成 2,048 个请求。每个请求打开并 `mmap` 一个 4 MiB 文件，读取映射计算 SHA-256，随后 `munmap` 并校验响应；诊断只统计服务 TGID 的命中。服务端和控制端代码在 [http/](experiments/mmap-cause-20261026/http/)。

SHA-256 是文件校验负载的实际工作，不是为了仓库或产物做哈希验证。Kbuild 和 HTTP 结构差别很大，不能把两者差异直接归因于单一因素。

## 主要观测：START 各部分都有差距

同一服务器、同一个 `57326bc` 采集器，**计数＋必要配对**，未采入口栈、未使用 timer/轮询。fentry 分段针对 `down_write_killable` 的目标写锁 START；普通 tracepoint 使用目标写锁 START，挂点覆盖并不完全相同。每一列是每轮均值的三轮中位数，单位 ns/次，**不是逐次延迟 p50**：

| 接入和负载 | 计数/筛选/key | 身份与记录准备 | map 插入 | 收尾 | START 总计 |
|---|---:|---:|---:|---:|---:|
| fentry，Kbuild | 25.77 | 18.63 | 137.71 | 13.95 | 197.24 |
| fentry，HTTP 32 | 95.60 | 43.36 | 720.08 | 26.72 | 886.17 |
| tracepoint，Kbuild | 33.35 | 20.66 | 161.23 | 14.83 | 225.98 |
| tracepoint，HTTP 32 | 130.13 | 62.98 | 775.90 | 37.55 | 1004.53 |

各列独立取中位数，不能要求逐列相加或两列中位数相减等于逐轮配对差值。逐轮配对后，map 插入占 fentry 总差距的 **83.4%–85.6%**，tracepoint 的 **78.6%–79.5%**；其他分段也均有差距。只保留开始/结束两个计时点时，fentry 的 Kbuild/HTTP 仍分别约 167/817 ns，因此额外分段计时不是整个差距的解释。诊断使用 `bpf_ktime_get_ns`，带检查点扰动；数值是回调计时，不应称为精确无扰动 CPU 周期。

两个 HTTP 分组各有一轮记录到 4,097 次目标写入口，而请求数预期为 4,096；TGID 核对正确，额外记录来源未采栈，保留了样本。移除任意一条的最大可能均值影响分别不超过 3.64/6.24 ns，不能把次数说成每轮都精确一致。

完整分组、直方图和逐轮数据：[归因结果](evidence/mmap-cause-20261026/归因结果.txt)、[分轮数据](evidence/mmap-cause-20261026/scoped-rows.json)、[归因计算](evidence/mmap-cause-20261026/attribution.json)、[验证摘要](evidence/mmap-cause-20261026/verification.json)。数据保留测量和汇总字段；未发布服务器路径、完整进程日志和其他运行遥测。

## 已做的控制实验及其边界

- **执行间隔与线程数**：单线程固定 CPU 的热循环约 149 ns；间隔 200 μs 并忙等约 183 ns，睡眠间隔约 213 ns。32 线程热循环约 205 ns；32 线程绑定同一 CPU 约 156 ns。各自单独不足以重现真实 HTTP 的全部差距。
- **前面的工作集**：相同线程固定 CPU、计算相同的 4 MiB 数据量时，反复访问 4 KiB 工作集约 230 ns；扫描 4 MiB 工作集约 327 ns。一次 4 MiB SHA 后紧接两次 `mprotect`，第一/第二次 START 分别约 312/177 ns；不做 SHA 的成对对照约 169/168 ns。结果支持此前执行内容和数据/代码路径的复用状态影响成本，但不能证明某级缓存未命中是唯一原因。
- **CPU 放置**：HTTP 服务线程固定到单 CPU 后，fentry START 约从 886 降到 696 ns，但仍高于 Kbuild。固定 CPU 也改变并发和调度，不能把下降全部归因于迁移。
- **map 控制**：单线程固定 CPU、SHA 后插入的首次/紧接第二次分别约 261/141 ns。提前查当前表首次约 210 ns；当前表先取还节点首次约 144 ns，但预热本身另花约 341 ns，带预热的完整 START 约 537 ns。这是归因操作，不是净优化。详见 [机制结果](evidence/map-internals-20261026/机制结果.txt) 与 [15 条分轮数据](evidence/map-internals-20261026/scoped-rows.json)。
- **测量能力**：目标机没有可用的 cycles/instructions 硬件 PMU，未获得有效缓存未命中计数；私有 tracefs 实例不支持 `function_graph`，所以该组只有 15/21 次控制完成，6 次函数图及对应参考被跳过。**没有测到**桶锁等待、空闲链表、复制各自的时长，也没有证明不存在争用。内核源码有递归防护；不要假定用另一个 kprobe 就能无遗漏测到运行中 BPF 的 map 内部路径。

## 不要混淆的另一组结果

早期 `44964f0` 的 Kbuild A/B/C 对照分别为 A 无挂钩、B 相同挂点空回调、C 完整采集（状态和入口栈、无 timer），每种 7 轮。CPU 合计还包括控制程序和观测程序；结果见 [Kbuild 分轮数据](evidence/kbuild-repro-20261026/scoped-rows.json) 与 [汇总](evidence/kbuild-repro-20261026/SUMMARY.txt)。它测的是整次工作负载的 CPU/墙钟增量，与上述单个 START 回调的分段计时不是同一口径。原始截图的环境、版本及单位未完全核实，不能声称已严格复现截图。

后来试验的“线程记录复用”是另一套候选，不是解释原始 Kbuild 结果的前提。它在高频合成写锁下有收益，但带入口栈和轮询的 HTTP 总 CPU 收益不稳定，且线程遍历增加观测进程 CPU；目前没有证据说整体已达到 Kbuild 的单次回调水准。

## 交给 agent 的具体任务

1. 独立复核实际调用链、计时边界、目标进程过滤、读写和降级语义，检查证据有没有口径问题；区分被触发的全局回调、目标命中、START/RETURN/RELEASE 和业务总 CPU。
2. 在原始插入/删除实现上，提出并验证可以区分 **CPU 放置与竞争、工作集/路径历史、桶锁、空闲节点、复制、调度和计时扰动** 的方案；特别要解释 HTTP 的其他三个分段为什么也慢。说明每项实验可以或不能排除什么。
3. 如果当前机器不能测出 map 内部，明确原因，设计在支持 PMU 或独立函数图的 Linux 环境中的可重复实验；不要把缺失数据记为零，也不要臆测缓存层级、频率或原子重试次数。
4. 给出对照、原始记录、每轮均值、样本数和波动范围。若提出优化，要保留配对、降级、状态、入口栈及活跃记录，比较**业务＋观测器＋控制器**的 CPU 与业务表现；预热自身成本也必须计入。

## 在自己的 Linux 环境运行

仓库提供 [准备入口](experiments/mmap-cause-20261026/prepare_repro.py)：它把采集器和诊断程序复制到单独的工作目录，生成 HTTP 文件、从本机内核 BTF 生成头文件并编译程序。原始实验脚本也保留在仓库中。

需要 Linux x86-64 或 ARM64、支持相应挂点的内核及 `/sys/kernel/btf/vmlinux`、Python 3.9+、能编译 BPF 的 Clang、gcc、bpftool，以及 libbpf、libelf、zlib 和 OpenSSL 的开发文件。运行时需要加载 BPF 的管理员权限。fentry 和 mmap_lock tracepoint 是否可用取决于实际内核。

先做 HTTP 和单线程受控负载的短测：

```bash
git clone https://github.com/shuind/lock-bench.git
cd lock-bench/experiments/mmap-cause-20261026
python3 prepare_repro.py --workdir /tmp/mmap-lock-repro
sudo python3 /tmp/mmap-lock-repro/run.py --local-smoke \
  --only fentry-http-32 tracepoint-http-32 native-hot-1-single
```

输出位于工作目录新建的 `results-*`，包括 `rows.json`、`summary.json`、每轮诊断和 collector 数据。短测的 HTTP 请求数为 128，每种条件只运行一次，用于检查能否运行；正式对照去掉 `--local-smoke` 并设置 `--rounds 3`。准备过程生成的是新的 4 MiB 测试文件，内容不保证与原服务器文件相同，采集数据也受本机内核和硬件影响，不能当作原机复现。

要运行 Kbuild，提供一份完整 Linux 源码，准备入口会将其复制到新的工作目录，再在副本上执行 `headers_install`：

```bash
python3 prepare_repro.py --workdir /tmp/mmap-lock-kbuild \
  --kernel-src /path/to/linux-source
sudo python3 /tmp/mmap-lock-kbuild/run.py --rounds 3 \
  --only fentry-kbuild fentry-http-32 tracepoint-kbuild tracepoint-http-32
```

默认导出当前机器架构的 UAPI 头；可指定 `--kernel-arch arm64` 或 `--kernel-arch x86`。源码树和架构不同，导出的文件数量、字节数也会不同。实验会清理**工作目录内复制的** `kernel/usr/include`，使每轮都重新导出。若系统未启用 BPF 运行统计，准备后的运行器使用临时统计 FD，运行结束后关闭，不修改系统 `bpf_stats_enabled` 设置。

上述准备和 HTTP、fentry、tracepoint、原生及 Kbuild 短测已在本地 WSL Linux x86-64 验证；WSL 数据不能作为 ARM64 服务器的结果。内核不同或缺少权限时，应检查具体加载错误。仓库只含源码和裁剪后的分轮数据，不含已编译程序或大型内核树。
