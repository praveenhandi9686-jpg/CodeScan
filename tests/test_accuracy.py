import pytest
from analyzers import analyze_code
from tests.corpus import CLEAN, BUGGY

@pytest.mark.parametrize("lang", CLEAN)
def test_clean_code_has_zero_findings(lang):
    assert [(f["line_number"], f["title"]) for f in analyze_code(lang.split("#")[0], CLEAN[lang])] == []

@pytest.mark.parametrize("key", BUGGY)
def test_buggy_code_exact_findings(key):
    code, expected = BUGGY[key]
    got = {(f["line_number"], f["title"]) for f in analyze_code(key.split("#")[0], code)}
    assert got == expected, f"extra={got - expected} missing={expected - got}"
