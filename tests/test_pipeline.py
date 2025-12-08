import os
from redops.pipelines.runner import run_pipeline

def test_osint_metadata_pipeline(tmp_path):
    pipeline_path = "config/pipelines/osint_metadata_pipeline.json"
    target = "example.com"
    images = ["img1.jpg"]
    documents = ["doc1.pdf"]
    ctx = run_pipeline(pipeline_path, target, images, documents)
    assert ctx is not None
    assert "osint_profile" in ctx.data
    assert "image_metadata" in ctx.data
    assert "document_metadata" in ctx.data

def test_pipeline_missing_file():
    ctx = run_pipeline("nonexistent_pipeline.json", "test", [], [])
    assert ctx is None

def test_pipeline_bad_target():
    from redops.pipelines.runner import run_pipeline
    ctx = run_pipeline("config/pipelines/osint_metadata_pipeline.json", "", [], [])
    assert ctx is not None

def test_pipeline_step_error(monkeypatch):
    # Simulate error in a module function
    import redops.modules.recon.domains
    original_func = redops.modules.recon.domains.osint_profile
    def error_func(*a, **kw): raise Exception("module step error")
    monkeypatch.setattr(redops.modules.recon.domains, "osint_profile", error_func)
    ctx = run_pipeline("config/pipelines/osint_metadata_pipeline.json", "test", [], [])
    assert ctx is not None
    monkeypatch.setattr(redops.modules.recon.domains, "osint_profile", original_func)
