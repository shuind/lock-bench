"""Make only explicit benchmark-control changes to the pinned upstream source."""

import difflib
from pathlib import Path

HERE = Path(__file__).resolve().parent
original = (HERE / 'upstream/main.cpp').read_text()
source = original


def change(old, new, count=1):
    global source
    assert source.count(old) == count, (old, source.count(old), count)
    source = source.replace(old, new)


change('#include <malloc.h>', '#include <malloc.h>\n#include "progress.h"')
change('std::mt19937_64 gen(rd());', 'std::mt19937_64 gen(0x20261014ULL + thread_num);')
change('std::mt19937 gen(rd());', 'std::mt19937 gen(0x20261014U + thread_num);')
change(
    '        data.sort();\n\n        LOG("Iteration #" << iteration);',
    '        data.sort();\n        if (iteration == 1) benchReady(thread_num,2,0,data.size());\n        else benchAllocate(data.size());\n        benchIteration();\n\n        LOG("Iteration #" << iteration);',
)
change(
    '                    size_t elements_needed =',
    '                    benchVisit(max_steps);\n                    size_t elements_needed =',
)
change(
    '                    while (data.size() < elements_needed)\n                        data.insert(iter, gen());',
    '                    size_t size_before = data.size();\n                    while (data.size() < elements_needed)\n                        data.insert(iter, gen());\n                    benchAllocate(data.size() - size_before);',
)
change(
    '        MappedFile mapped(filename);\n        size_t * content',
    '        MappedFile mapped(filename);\n        if (iteration == 1) {\n            if (fsync(mapped.fd)) throw std::runtime_error("File fsync failed");\n            if (posix_fadvise(mapped.fd,0,0,POSIX_FADV_DONTNEED)) throw std::runtime_error("File cache preparation failed");\n            benchReady(thread_num,1,mapped.size,0);\n        }\n        benchIteration();\n        size_t * content',
)
change(
    '                    size_t available =',
    '                    benchVisit(max_steps);\n                    size_t available =',
)
change(
    '        threads = memory_threads + file_threads;',
    '        threads = memory_threads + file_threads;\n        benchInit(threads);',
)
change(
    '        std::this_thread::sleep_for(std::chrono::milliseconds(delay_memory_ms));\n        for (int i = 0; i < memory_threads;',
    '        if (!benchHeader) std::this_thread::sleep_for(std::chrono::milliseconds(delay_memory_ms));\n        for (int i = 0; i < memory_threads;',
)
change(
    '        for (auto& t : workers)\n            t.join();',
    '        if (benchHeader) benchSession();\n        for (auto& t : workers)\n            t.join();',
)
(HERE / 'workload.cpp').write_text(source)
(HERE / 'workload.diff').write_text(
    ''.join(
        difflib.unified_diff(
            original.splitlines(True),
            source.splitlines(True),
            fromfile='upstream/main.cpp',
            tofile='workload.cpp',
        )
    )
)
print(
    'SOURCE READY: preparation gate, deterministic seeds and common per-worker progress counters; original scan/allocation loops retained.'
)
