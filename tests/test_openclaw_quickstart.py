from pathlib import Path

from reposhield.openclaw_quickstart import generate_openclaw_quickstart


def test_openclaw_quickstart_generates_start_files(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    result = generate_openclaw_quickstart(repo, tmp_path / "reposhield", model="gpt-test")

    ps1 = Path(result["start_powershell"])
    cmd = Path(result["start_cmd"])
    provider = Path(result["provider_config"])
    assert ps1.exists()
    assert cmd.exists()
    assert provider.exists()
    assert "gateway-start" in ps1.read_text(encoding="utf-8")
    assert "reposhield-local" in provider.read_text(encoding="utf-8")
    assert result["base_url"] == "http://127.0.0.1:8765/v1"
