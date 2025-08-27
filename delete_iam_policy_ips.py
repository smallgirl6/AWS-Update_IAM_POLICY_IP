import boto3
import json

iam = boto3.client('iam')

# 削除したい IP のリスト（複数可）
DELETE_IPS = ["11.11.11.11/28", "13.13.13.13/28"]

# 更新対象のポリシー ARN のリスト
POLICY_ARNS = [
    "arn:aws:iam::AccountID:policy/test1",
    "arn:aws:iam::AccountID:policy/test3",
    "arn:aws:iam::AccountID:policy/test4",
]

def ensure_list(value):
    """値が文字列/リスト/None のいずれであっても、必ずリストに正規化して返す。
    - IAM ポリシーの aws:SourceIp は「単一文字列」または「文字列配列」の両方があり得る。
    - 後続処理（集合演算による削除等）を安定させるため、リストに統一する。
    """
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

def ensure_space_for_new_version(policy_arn):
    """Managed Policy は最大 5 バージョンまで。
    新規バージョン作成前にバージョン数を確認し、
    5 件に達している場合は「デフォルトではない最古のバージョン」を削除して空きを確保する。
    ※ デフォルトバージョンは削除不可のため対象外。
    """
    versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
    if len(versions) < 5:
        return  # 5 未満なら何もしない

    # デフォルトではないバージョンのみ抽出
    non_default = [v for v in versions if not v['IsDefaultVersion']]
    if not non_default:
        raise RuntimeError(f"No non-default versions available to delete for {policy_arn}")

    # 作成日時が古い順に並べ、最古のものを 1 件削除
    non_default.sort(key=lambda v: v['CreateDate'])
    oldest_vid = non_default[0]['VersionId']
    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest_vid)

def policy_doc_to_sorted_json(doc):
    """ポリシー JSON を「キー順ソート＋余計な空白除去」で標準化し、比較しやすい文字列にする。
    - 目的：実質内容が同一なのにキー順や空白の違いで「差分あり」と誤検知するのを防ぐ。
    - sort_keys=True でキー順を固定、separators で空白を抑制。
    """
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))

with open("updated_policies.txt", "w") as f:
    for policy_arn in POLICY_ARNS:
        try:
            # 現在のデフォルト版のバージョン ID を取得
            policy = iam.get_policy(PolicyArn=policy_arn)
            default_version_id = policy['Policy']['DefaultVersionId']

            # そのバージョンのポリシー本文（Document）を取得
            pv = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
            policy_doc = pv['PolicyVersion']['Document']

            # 変更前の標準化 JSON を作っておく（後で差分判定に使う）
            before = policy_doc_to_sorted_json(policy_doc)

            # Statement を取り出す
            statements = policy_doc.get('Statement')
            if statements is None:
                # Statement 自体が無い場合は今回の更新対象外
                msg = f"[NO STATEMENT] {policy_arn} (default {default_version_id})"
                print(msg)
                f.write(msg + "\n")
                continue
            if not isinstance(statements, list):
                statements = [statements]

            changed = False  # 実際に内容変更があったかどうか

            # 各 Statement を確認し、Condition.IpAddress.aws:SourceIp があるものだけ更新
            for stmt in statements:
                cond = stmt.get('Condition')
                if not cond:
                    continue  # Condition が無いならスキップ
                ip_cond = cond.get('IpAddress')
                if not ip_cond:
                    continue  # IpAddress 条件が無いならスキップ
                source_ip = ip_cond.get('aws:SourceIp')
                if source_ip is None:
                    continue  # aws:SourceIp が無いならスキップ

                # aws:SourceIp を必ずリスト化（単一文字列のケースに備える）
                current_ips = ensure_list(source_ip)

                # 現在の IP から削除対象 IP を差集合で引く。
                # set(current) - set(DELETE_IPS) によって指定した IP を取り除く。
                merged = sorted(set(current_ips) - set(DELETE_IPS))

                # 差異があれば書き戻して変更フラグを立てる
                if merged != current_ips:
                    ip_cond['aws:SourceIp'] = merged
                    changed = True

            # 変更後の標準化 JSON を作成し、before/after を比較
            after = policy_doc_to_sorted_json(policy_doc)

            # 差分が無ければバージョンを増やさない
            if not changed or before == after:
                msg = f"[NO CHANGE] {policy_arn} (default {default_version_id})"
                print(msg)
                f.write(msg + "\n")
                continue

            # 新規バージョン作成前に、5本上限の場合は最古の非デフォルト版を削除して空きを確保
            ensure_space_for_new_version(policy_arn)

            # 新しいポリシーバージョンを作成し、デフォルトに設定
            iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(policy_doc),
                SetAsDefault=True
            )

            msg = f"[UPDATED] {policy_arn} (prev default {default_version_id})"
            print(msg)
            f.write(msg + "\n")

        except iam.exceptions.NoSuchEntityException:
            # 対象のポリシーARNが存在しない場合はスキップ
            msg = f"[SKIP] {policy_arn} not found"
            print(msg)
            f.write(msg + "\n")
        except Exception as e:
            # それ以外のエラーを記録して次の ARN へ進む
            msg = f"[ERROR] {policy_arn}: {e}"
            print(msg)
            f.write(msg + "\n")