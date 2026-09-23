"""
Phase 09 — Docker & Deployment Tests
Validates: docker-compose.yml structure, Dockerfile syntax, .env.example completeness,
nginx.conf SPA routing config — no Docker daemon required.
"""
import os
import re
import yaml
import pytest

DEPLOYMENT_DIR = os.path.join(os.path.dirname(__file__), "..")
COMPOSE_FILE = os.path.join(DEPLOYMENT_DIR, "docker-compose.yml")
BACKEND_DOCKERFILE = os.path.join(DEPLOYMENT_DIR, "Dockerfile.backend")
FRONTEND_DOCKERFILE = os.path.join(DEPLOYMENT_DIR, "Dockerfile.frontend")
NGINX_CONF = os.path.join(DEPLOYMENT_DIR, "nginx.conf")
ENV_EXAMPLE = os.path.join(DEPLOYMENT_DIR, ".env.example")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_compose():
    with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ─────────────────────────────────────────────────────────────────────────────
# docker-compose.yml tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDockerCompose:
    @pytest.fixture(scope="class")
    def compose(self):
        return load_compose()

    def test_compose_file_exists(self):
        assert os.path.isfile(COMPOSE_FILE)

    def test_compose_is_valid_yaml(self, compose):
        assert compose is not None

    def test_compose_has_services_key(self, compose):
        assert "services" in compose

    def test_three_services_defined(self, compose):
        services = compose["services"]
        assert len(services) == 3, f"Expected 3 services, got {len(services)}: {list(services)}"

    def test_backend_service_present(self, compose):
        assert "backend" in compose["services"]

    def test_frontend_service_present(self, compose):
        assert "frontend" in compose["services"]

    def test_redis_service_present(self, compose):
        assert "redis" in compose["services"]

    def test_backend_has_healthcheck(self, compose):
        hc = compose["services"]["backend"].get("healthcheck")
        assert hc is not None, "backend missing healthcheck"
        assert hc.get("test"), "backend healthcheck test command missing"

    def test_redis_has_healthcheck(self, compose):
        hc = compose["services"]["redis"].get("healthcheck")
        assert hc is not None, "redis missing healthcheck"

    def test_frontend_depends_on_backend(self, compose):
        deps = compose["services"]["frontend"].get("depends_on", {})
        assert "backend" in deps

    def test_backend_depends_on_redis(self, compose):
        deps = compose["services"]["backend"].get("depends_on", {})
        assert "redis" in deps

    def test_named_volumes_defined(self, compose):
        volumes = compose.get("volumes", {})
        assert "redis-data" in volumes
        assert "backend-logs" in volumes

    def test_network_defined(self, compose):
        networks = compose.get("networks", {})
        assert "aegistrace-net" in networks

    def test_backend_port_exposed(self, compose):
        ports = compose["services"]["backend"].get("ports", [])
        assert any("8000" in str(p) for p in ports), "backend port 8000 not exposed"

    def test_frontend_port_exposed(self, compose):
        ports = compose["services"]["frontend"].get("ports", [])
        assert any("80" in str(p) for p in ports), "frontend port 80 not exposed"


# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDockerfileBackend:
    def test_file_exists(self):
        assert os.path.isfile(BACKEND_DOCKERFILE)

    def test_uses_python_base_image(self):
        content = read_file(BACKEND_DOCKERFILE)
        assert re.search(r"FROM python:3\.\d+", content), "Missing Python base image"

    def test_exposes_port_8000(self):
        content = read_file(BACKEND_DOCKERFILE)
        assert "EXPOSE 8000" in content

    def test_has_healthcheck(self):
        content = read_file(BACKEND_DOCKERFILE)
        assert "HEALTHCHECK" in content

    def test_runs_as_non_root(self):
        content = read_file(BACKEND_DOCKERFILE)
        # Should add a non-root user
        assert re.search(r"adduser|USER aegis", content), "Should run as non-root"

    def test_copies_requirements(self):
        content = read_file(BACKEND_DOCKERFILE)
        assert "COPY requirements.txt" in content

    def test_pip_no_cache(self):
        content = read_file(BACKEND_DOCKERFILE)
        assert "--no-cache-dir" in content


class TestDockerfileFrontend:
    def test_file_exists(self):
        assert os.path.isfile(FRONTEND_DOCKERFILE)

    def test_multi_stage_build(self):
        content = read_file(FRONTEND_DOCKERFILE)
        from_count = len(re.findall(r"^FROM ", content, re.MULTILINE))
        assert from_count >= 2, "Expected multi-stage build (>= 2 FROM statements)"

    def test_uses_node_builder(self):
        content = read_file(FRONTEND_DOCKERFILE)
        assert re.search(r"FROM node:\d+", content), "Missing Node.js builder stage"

    def test_uses_nginx_runtime(self):
        content = read_file(FRONTEND_DOCKERFILE)
        assert "nginx" in content.lower(), "Missing nginx runtime stage"

    def test_exposes_port_80(self):
        content = read_file(FRONTEND_DOCKERFILE)
        assert "EXPOSE 80" in content

    def test_runs_npm_build(self):
        content = read_file(FRONTEND_DOCKERFILE)
        assert "npm run build" in content


# ─────────────────────────────────────────────────────────────────────────────
# nginx.conf tests
# ─────────────────────────────────────────────────────────────────────────────

class TestNginxConf:
    def test_file_exists(self):
        assert os.path.isfile(NGINX_CONF)

    def test_spa_fallback_present(self):
        content = read_file(NGINX_CONF)
        assert "try_files" in content and "index.html" in content, (
            "SPA fallback (try_files ... /index.html) missing"
        )

    def test_api_proxy_present(self):
        content = read_file(NGINX_CONF)
        assert "proxy_pass" in content and "/api/" in content, (
            "API reverse proxy not configured"
        )

    def test_gzip_enabled(self):
        content = read_file(NGINX_CONF)
        assert "gzip on" in content

    def test_health_endpoint(self):
        content = read_file(NGINX_CONF)
        assert "/health" in content


# ─────────────────────────────────────────────────────────────────────────────
# .env.example tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvExample:
    @pytest.fixture(scope="class")
    def env_vars(self):
        content = read_file(ENV_EXAMPLE)
        vars_found = set()
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key = line.split("=")[0].strip()
                vars_found.add(key)
        return vars_found

    def test_file_exists(self):
        assert os.path.isfile(ENV_EXAMPLE)

    def test_has_demo_mode(self, env_vars):
        assert "DEMO_MODE" in env_vars

    def test_has_secret_key(self, env_vars):
        assert "SECRET_KEY" in env_vars

    def test_has_redis_url(self, env_vars):
        assert "REDIS_URL" in env_vars

    def test_has_uipath_vars(self, env_vars):
        required_uipath = {
            "UIPATH_ORCHESTRATOR_URL",
            "UIPATH_CLIENT_ID",
            "UIPATH_SIMULATION_MODE",
        }
        missing = required_uipath - env_vars
        assert not missing, f"Missing UiPath env vars: {missing}"

    def test_has_threat_intel_keys(self, env_vars):
        assert "VIRUSTOTAL_API_KEY" in env_vars
        assert "ABUSEIPDB_API_KEY" in env_vars
