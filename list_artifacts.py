import os
import json

REGISTRY = "registry"

rows = []
for f in os.listdir(REGISTRY):
    if not f.endswith(".json"):
        continue
    path = os.path.join(REGISTRY, f)
    try:
        with open(path, "r", encoding="utf-8") as fp:
            d = json.load(fp)
        rows.append((f, d.get("transform_version"), "SIGNED" if d.get("signature") else "UNSIGNED"))
    except Exception as e:
        rows.append((f, "ERROR", str(e)))

# stable output order for readability
rows.sort(key=lambda x: x[0])

for f, ver, sig in rows:
    print(f"{f}  |  {ver}  |  {sig}")