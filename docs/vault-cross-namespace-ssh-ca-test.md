# Vault Cross-Namespace SSH CA Test

## Summary

Vault Enterprise cross-namespace access로 다른 namespace의 SSH CA에 서명 요청이 가능한지 검증했다.

결론: 가능하다.

- 자신의 namespace token으로 타 namespace SSH CA에 서명 요청 가능
- 발급받은 SSH certificate로 해당 namespace CA를 신뢰하는 서버에 SSH 접속 가능
- cross-namespace group grant가 없는 조합은 403으로 차단됨

## Environment

| Item | Value |
| --- | --- |
| AWS region | `ap-northeast-2` |
| Instance ID | `i-00199ee2be3c2fa15` |
| Public IP | `3.39.247.218` |
| Instance type | `t3.large` |
| AMI | `hc-security-base-ubuntu-2204-20260629151937` |
| Vault version | `Vault v2.0.3+ent` |
| Vault storage | Integrated Storage, raft |
| Namespaces | `A`, `B`, `C` |
| Test report path | `/opt/vault-cross-namespace/report.json` |

Terraform verification result: `No changes`.

## Test Design

Created three independent Vault namespaces:

- `A`
- `B`
- `C`

Each namespace has:

- one `userpass` user
- one identity entity
- one internal group
- one SSH secrets engine mounted at `ssh-client-signer`
- one SSH CA
- one signing role named `client-role`

Cross-namespace access was enabled by setting:

```hcl
group_policy_application_mode = "any"
```

Cross-namespace group grants were configured as:

| Source token namespace | Target SSH CA namespace | Expected |
| --- | --- | --- |
| `A` | `B` | Allowed |
| `B` | `C` | Allowed |
| `C` | `A` | Allowed |
| `A` | `C` | Denied, negative control |

## Results

| Test | Result |
| --- | --- |
| Set `group_policy_application_mode=any` | PASS |
| Create namespaces `A`, `B`, `C` | PASS |
| Create one entity per namespace | PASS |
| Add each entity to local namespace group | PASS |
| Add source namespace entities to target namespace cross-access groups | PASS |
| Issue namespace tokens for `A`, `B`, `C` | PASS |
| `A` token requests SSH cert from `B` CA | PASS |
| `B` token requests SSH cert from `C` CA | PASS |
| `C` token requests SSH cert from `A` CA | PASS |
| `A` token requests SSH cert from `C` CA without grant | PASS, denied with 403 |
| SSH login with `A` token issued `B` CA cert to server trusting `B` CA | PASS, `ssh-ok` |
| SSH login with `B` token issued `C` CA cert to server trusting `C` CA | PASS, `ssh-ok` |
| SSH login with `C` token issued `A` CA cert to server trusting `A` CA | PASS, `ssh-ok` |

## Answers

### 다른 namespace의 SSH CA에 Cross-Namespace Access로 서명 요청이 가능한가?

가능하다.

`group_policy_application_mode=any`를 설정하고, target namespace의 identity group에 source namespace의 entity를 member로 추가하면 source namespace token으로 target namespace의 SSH CA signing endpoint를 호출할 수 있다.

### 자신의 namespace token으로 타 namespace CA cert 발급이 가능한가?

가능하다.

이번 테스트에서 다음 조합이 모두 성공했다:

- `A` namespace token으로 `B` namespace SSH CA cert 발급
- `B` namespace token으로 `C` namespace SSH CA cert 발급
- `C` namespace token으로 `A` namespace SSH CA cert 발급

단, cross-namespace group membership과 policy grant가 없는 조합은 허용되지 않는다. Negative control인 `A` token으로 `C` namespace CA 서명 요청은 `403 permission denied`로 차단되었다.

### 발급받은 cert로 해당 namespace를 신뢰하는 서버에 SSH 접속이 가능한가?

가능하다.

각 target namespace의 SSH CA public key를 서버의 `TrustedUserCAKeys`로 설정한 뒤, cross-namespace signing으로 발급받은 certificate를 사용해 SSH 접속을 검증했다. 세 조합 모두 `ssh-ok`를 반환했다.

## Implementation Notes

Vault `1.19.5+ent`에서는 현재 라이선스의 `platform-standard` module을 처리하지 못해 기동에 실패했다. 최종 테스트는 `Vault v2.0.3+ent`로 수행했다.

Vault Enterprise 2.x에서 해당 라이선스를 사용하기 위해 다음 설정을 사용했다:

```hcl
license_entitlement {
  edition = "platform-standard"
}
```

Vault Enterprise는 dev-mode in-memory storage 대신 raft storage로 실행했다.

SSH signing role에는 Vault 2.x에서 요구하는 `key_type="ca"`를 명시했다.

## Terraform Files

- `terraform/envs/vault-cross-namespace-test`
- `terraform/modules/vault-cross-namespace-ssh-ca-test`
- `terraform/modules/vault-cross-namespace-ssh-ca-test/templates/user_data.sh.tftpl`

## Cleanup

테스트 인스턴스는 현재 실행 중이므로 비용이 발생한다. 정리하려면 다음을 실행한다:

```bash
cd terraform/envs/vault-cross-namespace-test
terraform destroy \
  -var="key_name=Byeongwook" \
  -var='ssh_ingress_cidrs=["121.190.86.98/32"]' \
  -var="vault_license_secret_arn=$VAULT_LICENSE_SECRET_ARN"
```

`VAULT_LICENSE_SECRET_ARN`에는 Secrets Manager에 저장한 Vault Enterprise license secret ARN을 넣는다.

## References

- [Configure cross namespace access](https://developer.hashicorp.com/vault/docs/enterprise/namespaces/configure-cross-namespace-access)
- [Vault signed SSH certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
- [Vault SSH secrets engine API](https://developer.hashicorp.com/vault/api-docs/secret/ssh)
