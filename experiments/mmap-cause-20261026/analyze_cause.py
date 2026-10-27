"""Attribute the measured gap and document controlled, bounded conclusions."""
import json
from pathlib import Path
import statistics as st

HERE=Path(__file__).resolve().parent
OUT=HERE/'server-results'
load=lambda name:json.loads((OUT/name).read_text(encoding='utf-8'))
rows=load('rows.json');meta=load('metadata.json');verified=load('verification.json')
summaries={r['case']['name']:r for r in load('recomputed.json')}
assert verified['checks']in('PASS','PASS_WITH_NOTE')and verified['runs']==51


def describe(v):
    mid=st.median(v)
    return dict(median=mid,madn=st.median(abs(x-mid)for x in v)/0.6744897501960817,min=min(v),max=max(v),rounds=v)


def run(name,repeat):return next(r for r in rows if r['case']['name']==name and r['repeat']==repeat)
def total(name):return summaries[name]['total_ns']['median']
def component(name,part):return summaries[name]['components'][part]['median']


attribution={}
for method in('fentry','tracepoint'):
    trial=[]
    for n in range(3):
        a=run(method+'-http-32',n)['diagnostic'];b=run(method+'-kbuild',n)['diagnostic']
        gap=a['mean_ns']-b['mean_ns'];parts=[]
        for x,y in zip(a['components'],b['components']):
            d=x['mean_ns']-y['mean_ns'];parts.append(dict(name=x['name'],gap_ns=d,gap_share_pct=d/gap*100))
        assert abs(sum(p['gap_ns']for p in parts)-gap)<1e-8
        trial.append(dict(repeat=n,gap_ns=gap,parts=parts))
    attribution[method]=dict(gap_ns=describe([t['gap_ns']for t in trial]),trials=trial,
        component_gap_ns={p:describe([next(x['gap_ns']for x in t['parts']if x['name']==p)for t in trial])for p in meta['components']},
        component_share_pct={p:describe([next(x['gap_share_pct']for x in t['parts']if x['name']==p)for t in trial])for p in meta['components']})
paired={}
for name in('native-pair-hot-1-single','native-pair-hash-1-single'):
    pairs=[run(name,n)['diagnostic']['pair_profiles']for n in range(3)]
    paired[name]=dict(first_ns=describe([p[0]['mean_ns']for p in pairs]),second_ns=describe([p[1]['mean_ns']for p in pairs]),
        difference_ns=describe([p[0]['mean_ns']-p[1]['mean_ns']for p in pairs]),
        map_difference_ns=describe([p[0]['components'][2]['mean_ns']-p[1]['components'][2]['mean_ns']for p in pairs]))
extra_checkpoint=[]
for n in range(3):
    seg=run('fentry-http-32',n)['diagnostic']['mean_ns']-run('fentry-kbuild',n)['diagnostic']['mean_ns']
    plain=run('fentry-http-32-total',n)['diagnostic']['mean_ns']-run('fentry-kbuild-total',n)['diagnostic']['mean_ns']
    extra_checkpoint.append(dict(repeat=n,segmented_gap_ns=seg,total_only_gap_ns=plain,difference_ns=seg-plain))
effects=dict(attribution=attribution,pairs=paired,checkpoint_controls=extra_checkpoint,
     large_minus_small_working_set_ns=describe([run('native-hash-1-single',n)['diagnostic']['mean_ns']-run('native-hash-small-1-single',n)['diagnostic']['mean_ns']for n in range(3)]),
     default_minus_pinned_http_ns=describe([run('fentry-http-32',n)['diagnostic']['mean_ns']-run('fentry-http-32-pinned',n)['diagnostic']['mean_ns']for n in range(3)]))
(OUT/'attribution.json').write_text(json.dumps(effects,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

f=attribution['fentry'];t=attribution['tracepoint']
lines=['Kbuild 与 HTTP 的入口成本差异：归因结果','',
 '服务器 ARM64 / Linux 6.6；observer 57326bc；51次完整运行，17条件各3轮；计数＋必要配对，无栈、timer、轮询。',
 '计时仅统计测试服务TGID、make及其子进程或原生受控进程。四段之和、直方图、CPU计数均核对一致，采集错误及漏执行均为零。',
 '数值为每轮平均ns/次的三轮中位数，不是逐次延迟p50。临时测量版保留检查点与空计时参考，不能当作完全无扰动的原程序精确时间。','',
 '已经定位的主要结论：',
 f"HTTP 相对 Kbuild 的差距主要落在 mm_records 哈希表插入。fentry 三轮该段解释总差距的 {f['component_share_pct']['map_insert']['min']:.1f}%–{f['component_share_pct']['map_insert']['max']:.1f}%；tracepoint为 {t['component_share_pct']['map_insert']['min']:.1f}%–{t['component_share_pct']['map_insert']['max']:.1f}%。",'']
lines+=['入口分段，单位ns/次：','方案/负载 | 计数、筛选、key | PID与记录准备 | map插入 | 收尾 | 总计']
for name in('fentry-kbuild','fentry-http-32','fentry-http-32-pinned','tracepoint-kbuild','tracepoint-http-32'):
    lines.append(name+' | '+' | '.join(f'{component(name,p):.2f}'for p in meta['components'])+f' | {total(name):.2f}')
lines+=['各列独立取中位数，列相加可能略有差异；归因份额先每轮计算，因此不受中位数不可相加影响。','',
 '受控因果证据：',
 '1. 原生单线程固定CPU，相同mprotect加锁路径：热循环 '+f"{total('native-hot-1-single'):.2f}ns；间隔200us但忙等 {total('native-busy-1-single'):.2f}ns；睡眠间隔 {total('native-sleep-1-single'):.2f}ns。单独降低触发密度的这些对照，幅度远小于真实HTTP差距。",
 '2. 同一线程固定CPU，两种SHA都计算同样4MiB内容并执行1024次4KiB Update，仅实际地址工作集不同：反复访问4KiB '+f"{total('native-hash-small-1-single'):.2f}ns，扫描4MiB {total('native-hash-1-single'):.2f}ns；逐轮差值均为正。",
 '3. 同一线程固定CPU，一次SHA之后紧接两次mprotect：第一次 '+f"{paired['native-pair-hash-1-single']['first_ns']['median']:.2f}ns，第二次 {paired['native-pair-hash-1-single']['second_ns']['median']:.2f}ns。无SHA的相同保护方向成对对照为 {paired['native-pair-hot-1-single']['first_ns']['median']:.2f}/{paired['native-pair-hot-1-single']['second_ns']['median']:.2f}ns。说明先前执行内容及刚访问过的数据/路径的复用会显著改变成本；不能把全部差距解释成32线程竞争或保护方向。",
 '4. HTTP固定CPU后，服务线程迁移次数从默认三轮5936–6952次降为0；入口 '+f"{total('fentry-http-32'):.2f}ns 降到 {total('fentry-http-32-pinned'):.2f}ns，仍高于Kbuild。固定CPU同时改变可用并发和调度，下降幅度不能全部归因于迁移本身。",
 '5. 热循环从1线程到32线程（全部CPU），入口 '+f"{total('native-hot-1-single'):.2f}ns 到 {total('native-hot-32-all'):.2f}ns；32线程固定同一CPU为 {total('native-hot-32-single'):.2f}ns。只有线程数变多并不能重现真实HTTP的大差距。",'',
 '计时扰动和长尾核对：',
 '只保留首尾时间戳、使用原mm_start的对照：Kbuild '+f"{total('fentry-kbuild-total'):.2f}ns，HTTP {total('fentry-http-32-total'):.2f}ns；差距仍存在，说明内部额外检查点不是主要来源。",
 '真实fentry Kbuild/HTTP默认条件中，>=10us的回调占累计时间均不到1%；高均值不是被少数极长停顿主导。',
 '服务器runtime_identity全部为pid_namespace_ino=0、get_current_pid_tgid；身份准备不是WSL里较重的PID命名空间helper，不能照搬WSL的分段占比。','',
 '可以怎样理解map插入：',
 '它不仅复制一份记录，还要计算key的哈希、定位桶、进行内部同步、从预分配空闲元素中取节点、复制key/value并链接节点。最近访问的数据/代码、CPU位置和调用间的其它工作都会影响这段访问链路。',
 '本map已经使用预分配哈希表；“预分配”仍保留桶锁、空闲链表和元数据访问，不能把本次结果解释为每次都malloc。',
 '源代码核对：该服务器 kernel/bpf/hashtab.c:1098–1204（htab_map_update_elem）、1003–1077（alloc_htab_elem）、131–179（预分配判断和桶锁）；生产mm_insert见observer/mmap/state.bpf.h。','',
 '结论边界：',
 '实验支持“执行前历史/工作集局部性与CPU放置影响哈希表插入成本”，并定位了主要差值所在。它没有直接测出L1/L2/L3缺失率，也没有把哈希表内部的桶锁等待、freelist、数据复制分别计时，不能宣称某一级cache或某个内部锁已经被唯一证实。',
 '服务器PMU cycles/instructions报告not supported，cpufreq接口缺失；没有用不存在的数据断言CPU频率。系统steal/softirq快照覆盖准备、测量和清理，不能当作精确回调区间的计数。',
 '如果还需细分哈希表内部，可准备固定CPU下“插入前只读lookup预热”消融，并在具有PMU支持的同机采缓存计数，进一步区分数据局部性与内部同步；本轮未自动运行额外root实验。','',
 '数据备注：']
for note in verified['http_service_extra_entries']:
    lines.append(f"{note['case']} 第{note['repeat']+1}轮服务内记录{note['observed_service_write_entries']}次写入口，比请求预期多1次；服务TGID核对正确，并非其它进程。来源未采栈，未擅自删除样本。删除任意一个额外记录对该轮均值的最大可能影响不超过{note['maximum_mean_bias_ns']:.3f}ns，远小于主差距。")
lines+=['','原始数据、MADN、范围、逐CPU分布、调度快照、直方图与全部对照保存在rows.json、recomputed.json、attribution.json和VERIFIED_SUMMARY.txt。',
        '未改动公共REPORT.html、生产采集器、现有业务部署或统计开关；未推送仓库。原HTTP请求/校验逻辑不变，私有受控对照按计划改变CPU放置、间隔与工作集。','']
(OUT/'归因结果.txt').write_text('\n'.join(lines),encoding='utf-8')
(OUT/'下一步.txt').write_text('进一步拆哈希表内部的备选方案：固定CPU、保持同一加锁路径与相同工作量，对比插入前只读lookup预热；另在PMU可用的环境采集cache-miss/cycles/instructions。\n这些仅是后续方案，本轮未执行，也不能在未测量前宣称某级缓存或桶锁等待是唯一原因。\n',encoding='utf-8')
print('ATTRIBUTION_REPORT_WRITTEN',OUT/'归因结果.txt')
print('FENTRY_MAP_GAP_SHARE',f['component_share_pct']['map_insert'])
print('TRACEPOINT_MAP_GAP_SHARE',t['component_share_pct']['map_insert'])
