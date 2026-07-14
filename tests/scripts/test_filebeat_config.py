from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_filebeat_uses_filestream_container_parser_and_api_key() -> None:
    config = (ROOT / "portal/deploy/filebeat.yml").read_text(encoding="utf-8")

    assert "type: filestream" in config
    assert "- container:" in config
    assert "/var/lib/docker/containers/*/*.log" in config
    assert 'api_key: "${ELASTIC_FILEBEAT_API_KEY}"' in config
    assert 'index: "filebeat-security-lab-%{+yyyy.MM.dd}"' in config
    assert "username:" not in config
    assert "password:" not in config


def test_portal_runtime_packages_filebeat_without_embedding_a_key() -> None:
    compose = (ROOT / "portal/deploy/docker-compose.yml").read_text(encoding="utf-8")
    package_script = (ROOT / "scripts/package-portal-runtime.sh").read_text(encoding="utf-8")
    remote_script = (ROOT / "scripts/remote-deploy-portal.sh.tmpl").read_text(encoding="utf-8")

    assert "docker.elastic.co/beats/filebeat:8.17.0" in compose
    assert "/var/lib/docker/containers:/var/lib/docker/containers:ro" in compose
    filebeat_service = compose.split("  filebeat:\n", 1)[1].split("\nvolumes:", 1)[0]
    assert "network_mode: host" in filebeat_service
    assert 'cp "$PORTAL_DIR/deploy/filebeat.yml"' in package_script
    assert ".elastic_filebeat_ingest_api_key" in remote_script
    assert ".elastic_filebeat_read_api_key" in remote_script
    assert '"privileges":["read","view_index_metadata"]' in remote_script
    assert 'ELASTIC_FILEBEAT_READ_API_KEY=%s' in remote_script
    assert 'chmod 600 "$INSTALL_DIR/filebeat.env"' in remote_script
    assert "http://127.0.0.1:9200" in remote_script
    assert "http://host.docker.internal:9200" not in remote_script
    assert "FILEBEAT_CONFIG_API_KEY=" in remote_script
    assert "base64 -d" in remote_script
    assert '"$FILEBEAT_CONFIG_API_KEY"' in remote_script
    assert "unset FILEBEAT_CONFIG_API_KEY" in remote_script
    assert "ps --status running --services | grep -qx filebeat" in remote_script
    assert 'printf \'%s\' "$SECRET_JSON" > "$SECRET_FILE"' in remote_script
    assert "print(FILEBEAT_API_KEY)" not in remote_script
