from cti_pipeline.settings import load_settings


def test_load_settings_reads_dotenv_without_overriding_environment(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("LLM_MODEL", "env-model")
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "LLM_PROVIDER=openai_compatible",
                'LLM_MODEL="dotenv-model"',
                "LLM_API_KEY=dotenv-secret",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings()

    assert settings.llm_provider == "openai_compatible"
    assert settings.llm_model == "env-model"
    assert settings.llm_api_key == "dotenv-secret"
