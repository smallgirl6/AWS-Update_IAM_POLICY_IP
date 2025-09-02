import csv

INPUT_FILE = "input.csv"   # 入力CSVファイル
OUTPUT_FILE = "matched_ips.csv"  # 出力CSVファイル
TARGET_IPS = [
    "1111.1111.1111.1111",
    "2222.2222.2222.2222",
    "3333.3333.3333.3333",
]

# 列番号の指定（0始まり）
COL_D = 65   # BN列（Excelでは66列目）
COL_H = 3    # D列（Excelでは4列目）

results = []

# CSVを読み込み
with open(INPUT_FILE, newline='', encoding="utf-8") as f:
    reader = csv.reader(f)
    for row_num, row in enumerate(reader, start=1):  # row_numはExcelと同じ1始まり
        if len(row) > COL_H:  # H列（ここではD列）が存在するか確認
            h_value = row[COL_H]
            hits = [ip for ip in TARGET_IPS if ip in h_value]  # IPリストと照合
            if hits:
                d_value = row[COL_D] if len(row) > COL_D else ""  # BN列の値を取得
                results.append([row_num, d_value, h_value, ", ".join(hits)])

# 結果をCSVに出力
with open(OUTPUT_FILE, "w", newline='', encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Row", "BN_value", "D_value", "Matched_IPs"])
    writer.writerows(results)

print(f"完了。{len(results)} 行が一致し、{OUTPUT_FILE} に出力しました。")
