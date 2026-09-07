# IBM Security + HashiCorp Security Lab

[한국어](README.md) · [English](README.en.md)

## 목적

IBM 보안·운영 도구와 HashiCorp 제품의 신호를 포털에서 확인하고, 조사·승인·대응 흐름을 실습하는 AWS 기반 통합 보안 랩입니다. 각 제품의 관리 콘솔을 대체하는 프로젝트는 아닙니다.

## 기대 효과

- 제품별 이벤트를 공통 화면과 맥락으로 검토할 수 있습니다.
- 탐지 신호에서 조사·승인·대응까지의 운영 흐름을 연습합니다.
- Mock 커넥터로 시나리오를 준비하고 실제 연동 경계를 비교합니다.

## 주요 기능과 구성

- `portal/`: FastAPI, React, PostgreSQL 기반 포털
- `connectors/`: QRadar, Verify, Guardium, Instana, Turbonomic, Kubecost, Concert 및 HashiCorp 연동 코드
- `terraform/`, `k8s/`, `nomad/`: 인프라·워크로드 구성 예제
- Vault·Vault Radar·Boundary 신호, 감사 로그, 승인 기반 동작
- 문맥 기반 AI 분석 보조: 로컬 evidence 모드, 선택적 Bedrock; 대응 자동 실행은 하지 않음

## 시작하기

Docker Compose로 로컬 Mock 환경을 실행합니다. 환경 파일에서 `PORTAL_MODE=mock`, `CONNECTOR_MODE=mock`을 확인하세요.

```bash
cp portal/.env.example portal/.env
docker compose -f portal/docker-compose.yml up --build
```

포털: `http://localhost:5173` · 백엔드 상태: `http://localhost:8000/health`. AWS 실습은 `terraform/envs/lab/`의 입력값을 준비한 뒤 `terraform plan`으로 검토합니다.

## 문서

- [아키텍처](docs/architecture.md)
- [데모 시나리오](docs/demo-scenarios.md)
- [기업용 설치 조건](docs/enterprise-installation.md)
- [제품 연동](docs/ibm-integrations.md)
- [운영 Runbook](docs/runbook.md)
- [미구현 항목과 검토 사항](TODO.md)

## 범위와 제약사항

일부 실제 API 연동과 자동화는 예제·placeholder 단계입니다. 제품 라이선스와 API 권한이 별도로 필요하며, Terraform과 대응 작업은 검토 후 실행해야 합니다. 실서비스 준비 완료나 모든 제품의 실시간 연동을 의미하지 않습니다. 자격증명은 Vault·Secrets Manager·CI secret 등으로 제공하고 Git에 저장하지 마세요.
