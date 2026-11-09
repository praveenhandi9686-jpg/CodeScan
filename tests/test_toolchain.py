"""Real programs in every language (skipped when that language's toolchain is not installed on this machine)."""
import pytest
from analyzers import analyze_code
from services import runner, toolchain

HELLO = {"python": 'print("hi")', "javascript": 'console.log("hi")', "typescript": 'const s: string = "hi";\nconsole.log(s);',
 "java": 'public class Hello {\n  public static void main(String[] a) { System.out.println("hi"); }\n}', "c": '#include <stdio.h>\nint main(void) { puts("hi"); return 0; }',
 "cpp": '#include <iostream>\nint main() { std::cout << "hi\\n"; }', "csharp": 'using System;\nclass P { static void Main() { Console.WriteLine("hi"); } }',
 "go": 'package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }', "php": '<?php echo "hi\\n";', "ruby": 'puts "hi"', "rust": 'fn main() { println!("hi"); }',
 "kotlin": 'fun main() { println("hi") }', "swift": 'print("hi")', "bash": 'echo hi', "sql": "SELECT 'hi' AS msg;"}

@pytest.fixture(autouse=True)
def env(monkeypatch):
    for k in ("VERCEL", "RENDER"): monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_CODE_EXECUTION", "true")

@pytest.mark.parametrize("lang", HELLO)
def test_hello_world_runs(lang):
    r = runner.run_code(lang, HELLO[lang], timeout=30)
    if r["kind"] == "missing": pytest.skip(r["message"])
    assert r["kind"] == "ran" and r["phase"] == "run" and r["exit_code"] == 0 and "hi" in r["stdout"], r

def test_compile_error_is_reported_as_such():
    r = runner.run_code("c", "int main( {")
    if r["kind"] == "missing": pytest.skip("no C compiler")
    assert r["phase"] == "compile" and r["exit_code"] != 0 and r["stderr"] and [s["step"] for s in r["steps"]] == ["compile"]

def test_exit_code_stderr_and_timeout():
    r = runner.run_code("python", "import sys\nprint('out'); print('err', file=sys.stderr); sys.exit(3)")
    assert r["exit_code"] == 3 and "out" in r["stdout"] and "err" in r["stderr"]
    assert runner.run_code("python", "while True: pass", timeout=1)["timed_out"] is True

def test_html_and_css_previews():
    assert runner.run_code("html", "<p>x</p>")["kind"] == "preview"
    css = runner.run_code("css", ".btn { color: red } </style><script>alert(1)</script>")
    assert css["kind"] == "preview" and ".btn { color: red }" in css["html"] and "</style><script>" not in css["html"]

def test_sql_runs_and_blocks_attach():
    r = runner.run_code("sql", "CREATE TABLE t(a); INSERT INTO t VALUES (1),(2);\nSELECT a FROM t ORDER BY a;")
    assert "(2 row(s))" in r["stdout"]
    assert runner.run_code("sql", "ATTACH DATABASE 'x.db' AS x;")["exit_code"] != 0

def test_never_runs_on_hosting_and_explains_missing_tools(monkeypatch):
    monkeypatch.setenv("RENDER", "1"); assert runner.run_code("python", "print(1)")["kind"] == "disabled"
    monkeypatch.delenv("RENDER"); monkeypatch.setattr(toolchain, "which", lambda *a: None)
    r = runner.run_code("go", "package main"); assert r["kind"] == "missing" and "go.dev/dl" in r["message"]

@pytest.mark.parametrize("lang,code,line_text", [
    ("c", "int main() {\n  int x = 1\n  return 0;\n}\n", None), ("java", "public class A {\n  void m() { int x = \"s\"; }\n}\n", "incompatible types"),
    ("go", "package main\nfunc main() {\n\tx := 1\n}\n", "declared and not used"), ("rust", 'fn main() {\n    let x: i32 = "a";\n}\n', "mismatched types"),
    ("php", "<?php\necho ;\n", None), ("ruby", "def f\n  puts 1\n", None), ("bash", "if true; then\n  echo hi\n", None)])
def test_compiler_diagnostics_find_real_errors(lang, code, line_text, monkeypatch):
    monkeypatch.setenv("COMPILER_CHECKS", "true")
    diags, info = toolchain.diagnostics(lang, code)
    if not info["ran"]: pytest.skip(info["skipped"])
    assert any(d["sev"] == "error" for d in diags), (diags, info)
    if line_text: assert any(line_text in d["msg"] for d in diags)
    titles = [f["title"] for f in analyze_code(lang, code)]
    assert any(t.startswith("Compiler error") for t in titles) and "Syntax error" not in titles   # the compiler replaces the weaker syntax check

def test_compiler_checks_are_off_on_hosting_and_when_disabled(monkeypatch):
    monkeypatch.setenv("COMPILER_CHECKS", "true"); monkeypatch.setenv("RENDER", "1")
    assert toolchain.diagnostics("c", "int main(){}")[1]["ran"] is False
