import csv
import json
from typing import List, Any

INPUT_FILE = "input.csv"       # 入力CSVファイル
OUTPUT_FILE = "matched_ips.csv"  # 出力CSVファイル
TARGET_IPS = [
    "1111.1111.1111.1111",
    "2222.2222.2222.2222",
    "3333.3333.3333.3333",
]

# 列インデックス（0始まり）
SEARCH_COL = 2   # C列：IAMポリシー本文
VALUE_COL  = 0   # A列：出力で表示する値

def search_targets_in_text(text: str, targets: List[str]) -> List[str]:
    """文字列ベースの単純部分一致"""
    if text is None:
        return []
    t = str(text)
    return [ip for ip in targets if ip in t]

def iter_json_strings(node: Any):
    """JSONノード内の全ての文字列を走査"""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for v in node:
            yield from iter_json_strings(v)
    elif isinstance(node, dict):
        for v in node.values():
            yield from iter_json_strings(v)

def search_targets_in_policy_json(text: str, targets: List[str]) -> List[str]:
    """
    JSONとして解釈できれば Condition → (IpAddress|NotIpAddress) → aws:SourceIp を優先的にチェック。
    それ以外はJSON内の全文字列で部分一致を確認。
    """
    try:
        policy = json.loads(text)
    except Exception:
        return []

    hits = set()

    # 1) Condition → IpAddress/NotIpAddress → aws:SourceIp を探索
    def collect_source_ip_values(obj: Any) -> List[str]:
        values = []
        if isinstance(obj, dict):
            cond = obj.get("Condition")
            if isinstance(cond, dict):
                for key, val in cond.items():
                    if isinstance(key, str) and key.lower().endswith("ipaddress"):
                        if isinstance(val, dict):
                            sip = val.get("aws:SourceIp")
                            if isinstance(sip, list):
                                values.extend([str(x) for x in sip])
                            elif isinstance(sip, str):
                                values.append(sip)
            # 再帰的探索
            for v in obj.values():
                values.extend(collect_source_ip_values(v))
        elif isinstance(obj, list):
            for v in obj:
                values.extend(collect_source_ip_values(v))
        return values

    src_ips = collect_source_ip_values(policy)
    if src_ips:
        for ip in targets:
            if any(ip in s for s in src_ips):
                hits.add(ip)

    # 2) 見つからなければ全文字列で部分一致
    if not hits:
        for s in iter_json_strings(policy):
            for ip in targets:
                if ip in s:
                    hits.add(ip)

    return sorted(hits)

results = []

# CSVを読み込み
with open(INPUT_FILE, newline='', encoding="utf-8") as f:
    reader = csv.reader(f)
    for row_num, row in enumerate(reader, start=1):  # Excelと同じ1始まり
        if len(row) <= SEARCH_COL:
            continue

        policy_text = row[SEARCH_COL]

        # まずJSONベースで検索
        hits = search_targets_in_policy_json(policy_text, TARGET_IPS)

        # JSONで見つからなければ文字列包含
        if not hits:
            hits = search_targets_in_text(policy_text, TARGET_IPS)

        if hits:
            a_value = row[VALUE_COL] if len(row) > VALUE_COL else ""
            results.append([row_num, a_value, policy_text, ", ".join(hits)])

# 結果をCSVに出力
with open(OUTPUT_FILE, "w", newline='', encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Row", "A_value", "C_policy_raw", "Matched_IPs"])
    writer.writerows(results)

print(f"完了。{len(results)} 行が一致し、{OUTPUT_FILE} に出力しました。")
