TARGETS=("1.1.1.1/32" "2.2.2.2/32" "3.3.3.3/32")
OUTFILE="result.txt"

: > "$OUTFILE"

aws iam list-policies --scope Local --output json \
| jq -r '.Policies[] | [.Arn, .DefaultVersionId] | @tsv' \
| while IFS=$'\t' read -r arn ver; do
  hits="$(
    aws iam get-policy-version \
      --policy-arn "$arn" \
      --version-id "$ver" \
      --query 'PolicyVersion.Document' \
      --output json \
    | jq -r --argjson targets "$(printf '%s\n' "${TARGETS[@]}" | jq -R . | jq -s .)" '
        [ .. | objects
          | .Condition? // {}
          | objects
          | to_entries[]?
          | select(.key | test("IpAddress$"; "i"))
          | .value
          | if type=="object" then .["aws:SourceIp"] else empty end
          | if type=="array" then . else [.] end
          | .[]?
          | tostring
        ] as $ips
        | ($ips | map(select(. as $ip | $targets | index($ip))) | unique) as $hits
        | if ($hits|length) > 0 then $hits|join(",") else empty end
      '
  )"

  if [ -n "$hits" ]; then
    printf "%s\t%s\n" "$arn" "$hits" | tee -a "$OUTFILE"
  else
    printf "."
  fi
done
echo