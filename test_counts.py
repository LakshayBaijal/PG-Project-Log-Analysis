import json
from collections import Counter
from wireless_analyzer import split_traps, extract_trap_oid, TRAP_EVENT_MAP

with open("snmptrap-20250521.log", encoding="utf-8", errors="ignore") as f:
    text = f.read(1024*1024*20)

blocks = split_traps(text)
counts = Counter()
for b in blocks:
    oid = extract_trap_oid(b)
    counts[TRAP_EVENT_MAP.get(oid, "unknown")] += 1
print(counts.most_common(20))

