# Portal

Run local mock mode with `docker compose -f portal/docker-compose.yml up --build`. Backend exposes FastAPI endpoints; frontend fetches from the backend.

## AI security analyst

The portal includes a contextual AI analyst at `POST /api/assistant/chat`. It accepts only bounded finding, DB audit, application-risk, or dashboard metadata. Secret assignments, bearer/JWT tokens, AWS credentials, GitHub and HashiCorp tokens, and private keys are redacted before provider invocation. Responses remain review-only and can link to an existing dry-run action, but cannot execute remediation.

The safe default is the local evidence engine:

```dotenv
AI_ASSISTANT_PROVIDER=evidence
AI_ASSISTANT_MODEL_ID=
AI_ASSISTANT_REGION=ap-northeast-2
AI_ASSISTANT_MAX_TOKENS=700
```

Amazon Bedrock is optional:

```dotenv
AI_ASSISTANT_PROVIDER=bedrock
AI_ASSISTANT_MODEL_ID=<approved-model-id-or-inference-profile>
```

The portal instance role must be granted `bedrock:InvokeModel` for only the approved model or inference profile before enabling Bedrock. If Bedrock is unavailable, the endpoint fails over to evidence mode without exposing the provider error or user content.
