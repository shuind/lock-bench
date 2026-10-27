# 离线对照

读取开启、关闭观测两轮的结果，生成可直接打开的独立 HTML。可在 Linux 或 Windows 上运行，需要 Python 3.9+，无需管理员权限。

## 使用

两轮观测结束后，在仓库根目录执行：

```bash
python3 lockbench.py compare --on on.json --off off.json \
  --on-system on-system.jsonl --off-system off-system.jsonl \
  --output comparison.html
```

`--on`、`--off` 为 `lockbench.py run` 导出的最终 JSON。`--on-system`、`--off-system` 为对应轮次通过 `--system-output` 保存的完整 JSONL；省略时使用最终 JSON 内保留的样本。采样被截断时，页面会注明仅比较保留窗口。

只有原生 observer 二进制时，也可将其 JSON 作为 on/off 输入，但还需提供同期独立采集的系统 JSONL。建议让两轮使用相同的采样间隔。

| 参数 | 内容 | 默认值 |
|---|---|---|
| --on | 开启观测后的最终 JSON | 必填 |
| --off | 关闭观测后的最终 JSON | 必填 |
| --on-system | 开启轮完整系统 JSONL | 使用 on JSON 内的样本 |
| --off-system | 关闭轮完整系统 JSONL | 使用 off JSON 内的样本 |
| --output | 独立 HTML 路径 | comparison.html |

精简检出时，可用 `git sparse-checkout add analysis` 加上这一目录；分析不依赖 observer、system、bench 或 workload 的实现。

## 页面内容

- 两轮的采样起止时间、时长、样本数和逻辑 CPU 数。
- CPU 平均／采样峰值、I/O wait、内存平均／采样峰值、负载和 PSI 对照。
- 可切换指标、显示或隐藏任一轮的时间曲线，悬停查看采样值。
- 锁事件开始次数、累计慢提示、采集错误，以及导出的部分慢提示与入口栈地址。
- mmap_lock 的读、写入口分别显示触发次数、命中次数和命中率。fentry/kprobe 的触发包含其它 rwsem；tracepoint/raw 的触发来自 mmap_lock 事件。

CPU 利用率按有效区间的累计 ticks 计算，内存与负载按实际采样时长加权；PSI 使用区间累计停顿量。不可用数据不按零处理。百分比指标的差值单位为百分点。

曲线按各轮采样开始后的时间对齐。两轮应来自同一主机，并保持业务流量、工作量可比；系统资源变化不能直接代替业务吞吐、延迟和错误率。页面不会自动认定观测有无性能影响。

慢提示数量不等于独立锁数，可能含同一操作的不同阶段。最终 JSON 的事件与入口栈有导出数量限制；符号化栈和完整实时提示仍看原始 observer.log。

入口命中指识别目标并成功纳入跟踪，不含写锁降为读锁。命中率＝命中次数÷触发次数；没有触发时不计算比率，旧结果缺少字段时显示“未记录”。

cli.py 提供命令，compare.py 读取与统计数据，comparison.html 是页面模板。分析只读取已有文件，不加载探针或启动业务。
