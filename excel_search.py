# === 変更可能なパラメータ ===
INPUT_FILE  = "input.xlsx"          # 元のファイル
SHEET_NAME  = 0                     # シート名またはインデックス（0 は最初のシート）
OUTPUT_FILE = "matched_ips.xlsx"    # 出力ファイル名
TARGET_IPS  = [
    "1111.1111.1111.1111",
    "2222.2222.2222.2222",
    "3333.3333.3333.3333",
]
# ファイルにヘッダー行がない場合、列は「列の位置」で指定：D=4列目、H=8列目
# ファイルにヘッダー行がある場合（例：「Account」「IP」など）、下2行を列名の文字列に変更してください
USE_COLUMN_LETTERS = True           # True: 列番号で指定、False: 列名で指定
COL_D = 3 if USE_COLUMN_LETTERS else "D"   # D列（0始まりで3）
COL_H = 7 if USE_COLUMN_LETTERS else "H"   # H列（0始まりで7）
# ======================

# 読み込み
df = pd.read_excel(INPUT_FILE, sheet_name=SHEET_NAME, header=None if USE_COLUMN_LETTERS else 0)

# D列とH列を取得
col_D = df.iloc[:, COL_D] if USE_COLUMN_LETTERS else df[COL_D]
col_H = df.iloc[:, COL_H] if USE_COLUMN_LETTERS else df[COL_H]

# H列を文字列に変換して検索可能にする（NaNエラーを回避）
h_str = col_H.fillna("").astype(str)

# 各セルで一致するIPを抽出（複数一致も可能）
def hit_list(cell: str):
    hits = [ip for ip in TARGET_IPS if ip in cell]
    return hits

hits_series = h_str.apply(hit_list)

# 1つ以上のIPに一致した行を抽出
mask = hits_series.apply(len) > 0
matched = df.loc[mask].copy()

# 出力用データフレームを作成：行番号、D列の値、H列の値、一致したIP（カンマ区切り）
out = pd.DataFrame({
    "Row": matched.index + 1,  # Excel の行番号は 1 始まり
    "D_value": (matched.iloc[:, COL_D] if USE_COLUMN_LETTERS else matched[COL_D]).astype(str),
    "H_value": (matched.iloc[:, COL_H] if USE_COLUMN_LETTERS else matched[COL_H]).astype(str),
    "Matched_IPs": hits_series[mask].apply(lambda xs: ", ".join(xs)),
})

# Excel に保存
out_path = Path(OUTPUT_FILE)
out.to_excel(out_path, index=False)

print(f"完了。{len(out)} 行が一致しました。出力先: {out_path.resolve()}")
