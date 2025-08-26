import boto3
import json

# IAM クライアントを初期化
iam = boto3.client('iam')

# 追加したい新しい IP のリスト
new_ips = ["1.1.1.1/28", "2.2.2.2/28", "3.3.3.3/28"]

# 更新対象のポリシー ARN のリスト
policy_arns = [
  "arn:aws:iam::アカウントID:policy/test1",
  "arn:aws:iam::アカウントID:policy/test2",
  "arn:aws:iam::アカウントID:policy/test3",
]

for policy_arn in policy_arns:
    # 現在のデフォルトポリシーバージョンを取得
    policy = iam.get_policy(PolicyArn=policy_arn)
    default_version = policy['Policy']['DefaultVersionId']
    
    # ポリシードキュメントを取得
    policy_version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version
    )
    
    # ポリシードキュメントを修正
    policy_doc = policy_version['PolicyVersion']['Document']
    
    for statement in policy_doc['Statement']:
        if 'Condition' in statement and 'IpAddress' in statement['Condition']:
            current_ips = statement['Condition']['IpAddress']['aws:SourceIp']
            updated_ips = list(set(current_ips + new_ips))  # 結合して重複を削除
            statement['Condition']['IpAddress']['aws:SourceIp'] = updated_ips
    
    # 新しいポリシーバージョンを作成
    iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_doc),
        SetAsDefault=True
    )
    
    print(f"Updated {policy_arn}")
