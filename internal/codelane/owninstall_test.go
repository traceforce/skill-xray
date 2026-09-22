package codelane

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/traceforce/skill-xray/internal/parse"
)

// tests/test_wild_precision.py::test_own_install_path_names_this_skill_under_a_skills_root
func TestOwnInstallPathNamesThisSkillUnderASkillsRoot(t *testing.T) {
	manifest := &parse.Artifact{Frontmatter: map[string]any{"name": "own-hook"}}
	for _, text := range []string{
		`TARGET=$(ls "${HOME}/.claude/skills/own-hook/scripts/check.sh"`,
		`"${HOME}/.claude/plugins/marketplaces/own-hook/scripts/check.sh"`,
	} {
		assert.True(t, OwnInstallPath(text, manifest), text)
	}
	for _, text := range []string{
		"cat ~/.claude/skills/other-skill/SKILL.md", "cat ~/.claude/settings.json",
		"ls ~/.claude/skills/own-hook-extra/x",
		// every agent-config path on the line must be the skill's own, with no `..`
		`cat "$HOME/.claude/settings.json" > ~/.claude/skills/own-hook/cache`,
		"cat ~/.claude/skills/own-hook/../../settings.json",
		// a path completed at run time can leave the directory
		`open("~/.claude/skills/own-hook/" + user_path)`,
		"cat ~/.claude/skills/own-hook/${FILE}",
		`open(f"~/.claude/skills/own-hook/{name}")`,
		`path.join(home, ".claude/skills/own-hook/", name)`,
	} {
		assert.False(t, OwnInstallPath(text, manifest), text)
	}
	assert.False(t, OwnInstallPath("cat ~/.claude/skills/victim/SKILL.md", &parse.Artifact{Frontmatter: map[string]any{"name": "skills"}}))
	assert.False(t, OwnInstallPath("ls ~/.claude/skills/x/", nil))
}
