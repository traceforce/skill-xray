"""Generate requirements.json from CPython packaging 24.2 and the oracle's hooks._is_exact_pin.

Run from the module root with the oracle on PYTHONPATH:
    PYTHONPATH=<oracle>/src python internal/pep508/testdata/gen_goldens.py
"""
import json
import pathlib

from packaging.requirements import InvalidRequirement, Requirement

from skill_xray.checks.hooks import _is_exact_pin

SHA = "0123456789abcdef0123456789abcdef01234567"

# (pytest test that exercises the input, or "edge", input)
CASES = [
    # tests/test_parse.py
    ("test_requirements_deps_pinned", "requests==2.32.3"),
    ("test_requirements_deps_pinned", "flask[async]>=3"),
    ("test_requirements_deps_pinned", "-r other.txt"),
    ("test_requirements_prefix_range_not_pinned", "requests==2.*"),
    ("test_pyproject_deps_parsed", "flask>=3"),
    ("test_pyproject_build_system_requires_captured", "setuptools"),
    ("test_pyproject_build_system_requires_captured", "poison==1"),
    ("test_pyproject_dependency_groups_captured", "pytest==8"),
    ("test_requirements_url_continuation_and_comment", "pkg @ https://h/p.whl#sha256=abc"),
    ("test_requirements_url_continuation_and_comment", "flask==3.0.0"),
    ("test_requirements_trailing_backslash_not_dropped", "evil==1.0"),
    ("test_requirements_vcs_and_local_surfaced", "git+https://h/r.git#egg=pkg"),
    ("test_requirements_vcs_and_local_surfaced", "./local"),
    ("test_pyproject_optional_dependencies_collected", "requests>=2"),
    ("test_pyproject_optional_dependencies_collected", "pytest==8.0.0"),
    ("test_requirements_continuation_is_linear", "a"),
    # tests/test_supply_chain.py
    ("test_requirements_unpinned_fires_pinned_is_silent", "flask>=2.0"),
    ("test_pyproject_unpinned_is_pypi", "requests>=2.0"),
    ("test_pyproject_unpinned_is_pypi", "click==8.1.7"),
    ("test_all_pinned_manifest_is_clean", "urllib3==2.2.2"),
    ("test_pep508_direct_url_reference_fires",
     "internal-lib @ https://artifacts.corp.example.com/internal-lib/latest"),
    ("test_pep508_direct_ref_reported_once_not_also_low_unpinned",
     "mylib @ https://example.com/mylib-1.0.tar.gz"),
    ("test_pep508_extras_do_not_duplicate_direct_reference", "requests[socks] @ https://host/pkg.whl"),
    # tests/test_hooks.py (uvx/pipx specs reach Requirement())
    ("test_floating_mcp_package_reports", "tool~=1.4"),
    ("test_floating_mcp_package_reports", "tool"),
    ("test_pinned_or_local_mcp_server_does_not_report_floating_package", "tool==1.4.0"),
    ("test_pinned_or_local_mcp_server_does_not_report_floating_package", "tool==1"),
    ("test_python_wildcard_pin_is_still_floating", "tool==1.4.*"),
    ("test_pipx_python_option_value_is_not_the_package", "tool==1.0"),
    ("test_pep508_direct_reference_sha_is_a_pin", f"tool @ git+https://example.invalid/repo.git@{SHA}"),
    ("test_direct_reference_sha_with_subdir_fragment_is_a_pin",
     f"tool @ git+https://example.invalid/repo.git@{SHA}#subdirectory=python"),
    ("test_pep508_file_reference_is_local_pin", "tool @ file:///workspace/tool"),
    ("test_flat_mcp_map_and_snake_case_wrapper_are_supported", "snake-tool"),
    # instruction.md 4.4 verified behaviour and grammar edges
    ("edge", "tool@1.0"),
    ("edge", "tool=="),
    ("edge", "==1.0"),
    ("edge", "_bad==1"),
    ("edge", "tool ==1.0;"),
    ("edge", "tool==1.0 ;"),
    ("edge", "tool[extra]==1.0; python_version>'3'"),
    ("edge", "tool >= 1, == 2"),
    ("edge", "tool==abc"),
    ("edge", "tool===anything"),
    ("edge", "tool==="),
    ("edge", "tool===1,==2"),
    ("edge", "tool~=1"),
    ("edge", "tool~=1.0"),
    ("edge", "tool>=1.0+local"),
    ("edge", "tool==1.0+local"),
    ("edge", "tool==1.0+ABC"),
    ("edge", "tool==1.0a1.*"),
    ("edge", "tool>=1.0.*"),
    ("edge", "tool (>=1, <2)"),
    ("edge", "tool (>=1"),
    ("edge", "tool[a, b]"),
    ("edge", "tool[a b]"),
    ("edge", "tool[]"),
    ("edge", "tool[a,a]"),
    ("edge", "tool [x] >= 1"),
    ("edge", "  tool  "),
    ("edge", "tool==1.0\n"),
    ("edge", "tool==1.0\n\n"),
    ("edge", "tool==  1.0"),
    ("edge", "tool== 1.0 , >=0.5"),
    ("edge", "tool==1.0,==1"),
    ("edge", "tool==1.0,==1.0"),
    ("edge", "tool>=1.0,>=1"),
    ("edge", "tool~=1.0,~=1.0.0"),
    ("edge", "tool==1.0,==1.0.0"),
    ("edge", "tool==1.0a,==1.0a0"),
    ("edge", "tool==1.0.RC1"),
    ("edge", "tool==V1.0"),
    ("edge", "tool==1.0-1"),
    ("edge", "tool==1.0.dev"),
    ("edge", "tool==1.0.0abc"),
    ("edge", "tool==99999999999999999999999"),
    ("edge", "tool==1!2.0"),
    ("edge", "tool<1.0a1"),
    ("edge", "tool!=1.*"),
    ("edge", "TOOL==1"),
    ("edge", "tool."),
    ("edge", "tool-"),
    ("edge", ".tool"),
    ("edge", "tool==1.0 # c"),
    ("edge", "tool==1.0;python_version>'3'"),
    ("edge", "tool\u00a0==1"),
    ("edge", "tool==\u00a01"),
    ("edge", "tool==1\u00a0"),
    ("edge", "tool==\n1"),
    ("edge", "tool @ https://x y"),
    ("edge", "tool@"),
    ("edge", "tool @ url extra"),
    ("edge", "tool @ url ; python_version>'3'"),
    ("edge", "tool @ url ;"),
    ("edge", "tool @ url;"),
    ("edge", "tool @ file:tool"),
    ("edge", "tool @ git+https://h/r.git@abc"),
    ("edge", f"tool @ https://h/r.git@{SHA}?x=1"),
    ("edge", f"tool @ https://h/r.git@{SHA}x"),
    ("edge", "tool; extra == 'x'"),
    ("edge", 'tool; extra == "x" and os_name != \'nt\''),
    ("edge", "tool; (python_version>'3' or os_name=='nt') and implementation_name=='cpython'"),
    ("edge", "tool; python_version in '3.9 3.10'"),
    ("edge", "tool; 'x' not in extra"),
    ("edge", "tool; python_version not  in 'x'"),
    ("edge", "tool; python_version notin 'x'"),
    ("edge", "tool; python_version ~= '3'"),
    ("edge", "tool; python_version === '3'"),
    ("edge", "tool; python_version in'3'"),
    ("edge", "tool; foo"),
    ("edge", "tool; python_version"),
    ("edge", "tool; python_version >"),
    ("edge", "tool; python_version > 3"),
    ("edge", "tool; platform.version == 'x'"),
    ("edge", "tool; python_versionx == 'x'"),
    ("edge", "tool; (python_version == 'x'"),
    ("edge", "tool; python_version == 'x' and"),
    ("edge", "tool; python_version == 'x' andos_name == 'y'"),
    ("edge", "tool; python_version == 'x' or (os_name == 'y')"),
    ("edge", "tool[socks]==1.0,!=1.0.1"),
    ("edge", "tool>=1,<2"),
    ("edge", "tool >= 1 , < 2 ; extra == 'a'"),
    ("edge", ""),
    ("edge", "   "),
    ("edge", "tool@1.2.3"),
    ("edge", "tool@latest"),
    ("edge", "@scope/tool@1.2.3"),
    ("edge", "toolé==1"),
    ("edge", "1tool==1"),
    ("edge", "tool_x==1"),
    ("edge", "tool==1.0.*.*"),
    ("edge", "tool==1.0.*,==1.0.*"),
]

# hooks._is_exact_pin(runner, spec) inputs; npx specs come from test_hooks.py
PIN_SPECS = [c for _, c in CASES] + [
    "tool@1.2.3", "tool@latest", "tool@v1.2.3", "tool@1.2", "tool@1.2.3.4",
    "tool@1.2.3-beta.1+build.5", "@scope/tool@1.2.3", "@scope/tool",
    "alias@npm:@scope/tool@1.2.3", "alias@npm:tool@latest",
    f"github:owner/tool#{SHA}", "github:owner/tool", f"github:owner/tool@{SHA}#frag",
    f"git+https://h/r.git#{SHA}", f"git+https://h/r.git@{SHA}?x", f"git+https://h/r.git#{SHA}x",
    f"gitlab:o/t#{SHA}", f"bitbucket:o/t#{SHA}", f"git:o/t#{SHA}",
    "https://h/tool.tgz", "http://h/tool.tgz", "./local", "../local",
    "C:\\repo\\tool", "c:/repo/tool", "~/x", "/x", "file:x", "file:///x", "tool@1.2.3\n",
    f"github:owner/tool#{SHA}\n", "tool@\u0661.\u0662.\u0663",
]


def req_row(source, text):
    row = {"from": source, "input": text}
    try:
        r = Requirement(text)
    except InvalidRequirement:
        row["valid"] = False
        return row
    except ValueError as e:                      # InvalidSpecifier escapes Requirement()
        row["valid"] = False
        row["exception"] = type(e).__name__
        return row
    specs = sorted([s.operator, s.version] for s in r.specifier)
    row.update({
        "valid": True, "name": r.name, "url": r.url or "",
        "specifiers": specs, "specifier_str": str(r.specifier),
        "pinned": any(s.operator in ("==", "===") and "*" not in s.version for s in r.specifier),
    })
    return row


def pin_row(runner, spec):
    try:
        return {"runner": runner, "spec": spec, "pin": bool(_is_exact_pin(runner, spec))}
    except Exception as e:                       # noqa: BLE001 - recorded, not asserted
        return {"runner": runner, "spec": spec, "pin": None, "exception": type(e).__name__}


out = {
    "requirements": [req_row(s, c) for s, c in CASES],
    "exact_pin": [pin_row(r, s) for r in ("npx", "uvx", "pipx") for s in PIN_SPECS],
}
path = pathlib.Path(__file__).with_name("requirements.json")
path.write_text(json.dumps(out, indent=1, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
print(f"{len(out['requirements'])} requirement rows, "
      f"{len(out['exact_pin'])} exact_pin rows -> {path}")
