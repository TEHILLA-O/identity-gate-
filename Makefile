.PHONY: env up bootstrap test test-scim

env:
	python scripts/init_env.py

up:
	docker compose up --build -d

bootstrap:
	docker compose exec backend python -m app.bootstrap

test:
	python -m pytest backend/tests scim-target/test_server.py -q --tb=short

test-scim:
	python -m pytest scim-target/test_server.py -q --tb=short
