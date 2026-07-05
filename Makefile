help:
	@echo "targets: bootstrap portal-up portal-down test lint tf-fmt tf-validate seed demo-events qradar-event clean"
bootstrap:
	./scripts/bootstrap.sh
portal-up:
	docker compose -f portal/docker-compose.yml up --build
portal-down:
	docker compose -f portal/docker-compose.yml down
test:
	cd portal/backend && python -m pytest
	cd portal/frontend && npm test
lint:
	python -m compileall portal/backend/app connectors
tf-fmt:
	terraform -chdir=terraform/envs/lab fmt -recursive
tf-validate:
	terraform -chdir=terraform/envs/lab init -backend=false && terraform -chdir=terraform/envs/lab validate
seed:
	./scripts/seed-demo-data.sh
demo-events:
	./scripts/generate-demo-events.sh
qradar-event:
	python -c "from portal.backend.app.qradar_sender import send_event; from portal.backend.app.models import CommonEvent; print(send_event(CommonEvent(source_product='demo', event_type='test'), dry_run=True))"
clean:
	rm -rf portal/frontend/node_modules portal/frontend/dist portal/backend/.pytest_cache
