from redops.modules.ai_summarizer import summarize

def test_summarize_short():
    data = "Alert: Critical vulnerability found in server X."
    summary = summarize(data)
    assert "vulnerability" in summary

def test_summarize_long():
    data = "Alert " + ("A" * 500)
    summary = summarize(data)
    assert summary.endswith("...")
