package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sleuth-io/sx/internal/asset"
	"github.com/sleuth-io/sx/internal/bootstrap"
	"github.com/sleuth-io/sx/internal/clients"
	"github.com/sleuth-io/sx/internal/clients/opencode"
	"github.com/sleuth-io/sx/internal/lockfile"
	"github.com/sleuth-io/sx/internal/metadata"
	"github.com/sleuth-io/sx/internal/utils"
)

func init() {
	clients.Register(opencode.NewClient())
}

func TestOpenCodeClientDetection(t *testing.T) {
	env := NewTestEnv(t)
	t.Setenv("PATH", "")

	client, err := clients.Global().Get(clients.ClientIDOpenCode)
	if err != nil {
		t.Fatalf("OpenCode client not registered: %v", err)
	}

	if client.IsInstalled() {
		t.Error("OpenCode should not be detected without ~/.config/opencode directory")
	}

	opencodeDir := filepath.Join(env.HomeDir, ".config", "opencode")
	if err := os.MkdirAll(opencodeDir, 0755); err != nil {
		t.Fatalf("Failed to create OpenCode config dir: %v", err)
	}

	if !client.IsInstalled() {
		t.Error("OpenCode should be detected with ~/.config/opencode directory")
	}
}

func TestOpenCodeSupportedAssetTypes(t *testing.T) {
	client, err := clients.Global().Get(clients.ClientIDOpenCode)
	if err != nil {
		t.Fatalf("OpenCode client not registered: %v", err)
	}

	supported := []string{"skill", "command", "agent", "rule", "mcp"}
	for _, typeName := range supported {
		if !client.SupportsAssetType(asset.FromString(typeName)) {
			t.Errorf("OpenCode should support %s assets", typeName)
		}
	}

	unsupported := []string{"hook", "claude-code-plugin"}
	for _, typeName := range unsupported {
		if client.SupportsAssetType(asset.FromString(typeName)) {
			t.Errorf("OpenCode should not support %s assets", typeName)
		}
	}
}

func TestOpenCodeInstallAssets(t *testing.T) {
	env := NewTestEnv(t)
	client, err := clients.Global().Get(clients.ClientIDOpenCode)
	if err != nil {
		t.Fatalf("OpenCode client not registered: %v", err)
	}

	bundles := []*clients.AssetBundle{
		openCodeAssetBundle(t, env, "review-code", asset.TypeSkill, "SKILL.md", "Review this code carefully.", nil),
		openCodeAssetBundle(t, env, "run-tests", asset.TypeCommand, "COMMAND.md", "Run the test suite.", nil),
		openCodeAssetBundle(t, env, "security-auditor", asset.TypeAgent, "AGENT.md", "Audit security risks.", nil),
		openCodeAssetBundle(t, env, "go-style", asset.TypeRule, "RULE.md", "Prefer small Go functions.", nil),
		openCodeAssetBundle(t, env, "local-tools", asset.TypeMCP, "", "", &metadata.MCPConfig{Command: "node", Args: []string{"server.js"}, Env: map[string]string{"TOKEN": "test"}}),
	}

	resp, err := client.InstallAssets(context.Background(), clients.InstallRequest{
		Assets: bundles,
		Scope:  &clients.InstallScope{Type: clients.ScopeGlobal},
	})
	if err != nil {
		t.Fatalf("InstallAssets error: %v", err)
	}
	for _, result := range resp.Results {
		if result.Status != clients.StatusSuccess {
			t.Fatalf("%s status = %s, message = %s, error = %v", result.AssetName, result.Status, result.Message, result.Error)
		}
	}

	targetBase := filepath.Join(env.HomeDir, ".config", "opencode")
	assertFileContains(t, filepath.Join(targetBase, "skills", "review-code", "SKILL.md"), "compatibility: opencode")
	assertFileContains(t, filepath.Join(targetBase, "commands", "run-tests.md"), "Run the test suite.")
	assertFileContains(t, filepath.Join(targetBase, "agents", "security-auditor.md"), "Audit security risks.")
	assertFileContains(t, filepath.Join(targetBase, "rules", "go-style.md"), "Prefer small Go functions.")

	config := readOpenCodeConfigForTest(t, filepath.Join(targetBase, "opencode.json"))
	instructions, ok := config["instructions"].([]any)
	if !ok || !containsAnyString(instructions, "rules/go-style.md") {
		t.Fatalf("opencode.json instructions missing rule: %#v", config["instructions"])
	}
	mcp, ok := config["mcp"].(map[string]any)
	if !ok {
		t.Fatalf("opencode.json missing mcp map: %#v", config)
	}
	server, ok := mcp["local-tools"].(map[string]any)
	if !ok {
		t.Fatalf("opencode.json missing local-tools MCP: %#v", mcp)
	}
	if server["type"] != "local" {
		t.Fatalf("MCP type = %#v, want local", server["type"])
	}

	assets := make([]*lockfile.Asset, 0, len(bundles))
	for _, bundle := range bundles {
		assets = append(assets, bundle.Asset)
	}
	verify := client.VerifyAssets(context.Background(), assets, &clients.InstallScope{Type: clients.ScopeGlobal})
	for _, result := range verify {
		if !result.Installed {
			t.Errorf("%s should verify as installed: %s", result.Asset.Name, result.Message)
		}
	}
}

func TestOpenCodeBootstrapMCP(t *testing.T) {
	env := NewTestEnv(t)
	client, err := clients.Global().Get(clients.ClientIDOpenCode)
	if err != nil {
		t.Fatalf("OpenCode client not registered: %v", err)
	}

	path := client.GetBootstrapPath()
	expected := filepath.Join(env.HomeDir, ".config", "opencode", "opencode.json")
	if path != expected {
		t.Fatalf("GetBootstrapPath() = %q, want %q", path, expected)
	}

	opts := []bootstrap.Option{bootstrap.SleuthAIQueryMCP()}
	if err := client.InstallBootstrap(context.Background(), opts); err != nil {
		t.Fatalf("InstallBootstrap error: %v", err)
	}

	config := readOpenCodeConfigForTest(t, expected)
	mcp := config["mcp"].(map[string]any)
	if _, ok := mcp["sx"]; !ok {
		t.Fatalf("sx MCP not installed: %#v", mcp)
	}

	if err := client.UninstallBootstrap(context.Background(), opts); err != nil {
		t.Fatalf("UninstallBootstrap error: %v", err)
	}
	config = readOpenCodeConfigForTest(t, expected)
	if mcp, ok := config["mcp"].(map[string]any); ok {
		if _, ok := mcp["sx"]; ok {
			t.Fatalf("sx MCP should have been removed: %#v", mcp)
		}
	}
}

func TestOpenCodeNonInteractiveInitInstallsDefaultMCP(t *testing.T) {
	env := NewTestEnv(t)
	t.Setenv("PATH", "")

	opencodeDir := filepath.Join(env.HomeDir, ".config", "opencode")
	if err := os.MkdirAll(opencodeDir, 0755); err != nil {
		t.Fatalf("Failed to create OpenCode config dir: %v", err)
	}

	cmd := NewInitCommand()
	cmd.SetArgs([]string{"--type=git", "--repo-url=git@example.com:team/sx-vault.git"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	config := readOpenCodeConfigForTest(t, filepath.Join(opencodeDir, "opencode.json"))
	mcp, ok := config["mcp"].(map[string]any)
	if !ok {
		t.Fatalf("opencode.json missing mcp map: %#v", config)
	}
	server, ok := mcp["sx"].(map[string]any)
	if !ok {
		t.Fatalf("sx MCP not installed during non-interactive init: %#v", mcp)
	}
	if server["type"] != "local" {
		t.Fatalf("sx MCP type = %#v, want local", server["type"])
	}
}

func TestOpenCodeClientInfo(t *testing.T) {
	env := NewTestEnv(t)
	setupTestConfig(t, env.HomeDir, nil, nil)

	opencodeDir := filepath.Join(env.HomeDir, ".config", "opencode")
	if err := os.MkdirAll(opencodeDir, 0755); err != nil {
		t.Fatalf("Failed to create OpenCode config dir: %v", err)
	}

	infos := gatherClientInfo()
	for _, info := range infos {
		if info.ID != clients.ClientIDOpenCode {
			continue
		}
		if !info.Installed {
			t.Error("OpenCode should show as installed")
		}
		if info.Name != "OpenCode" {
			t.Errorf("Expected display name 'OpenCode', got %q", info.Name)
		}
		if info.Directory != opencodeDir {
			t.Errorf("Expected directory %q, got %q", opencodeDir, info.Directory)
		}
		return
	}

	t.Fatal("OpenCode not found in client info")
}

func openCodeAssetBundle(t *testing.T, env *TestEnv, name string, assetType asset.Type, promptFile, promptContent string, mcpConfig *metadata.MCPConfig) *clients.AssetBundle {
	t.Helper()

	dir := env.MkdirAll(filepath.Join(env.TempDir, "opencode-assets", name))
	meta := &metadata.Metadata{
		MetadataVersion: "1.0",
		Asset: metadata.Asset{
			Name:        name,
			Version:     "1.0.0",
			Type:        assetType,
			Description: "Description for " + name,
		},
	}
	switch assetType {
	case asset.TypeSkill:
		meta.Skill = &metadata.SkillConfig{PromptFile: promptFile}
	case asset.TypeCommand:
		meta.Command = &metadata.CommandConfig{PromptFile: promptFile}
	case asset.TypeAgent:
		meta.Agent = &metadata.AgentConfig{PromptFile: promptFile}
	case asset.TypeRule:
		meta.Rule = &metadata.RuleConfig{PromptFile: promptFile}
	case asset.TypeMCP:
		meta.MCP = mcpConfig
	}

	if err := metadata.Write(meta, filepath.Join(dir, "metadata.toml")); err != nil {
		t.Fatalf("failed to write metadata: %v", err)
	}
	if promptFile != "" {
		env.WriteFile(filepath.Join(dir, promptFile), promptContent)
	}

	zipData, err := utils.CreateZip(dir)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}

	return &clients.AssetBundle{
		Asset:    &lockfile.Asset{Name: name, Version: "1.0.0", Type: assetType},
		Metadata: meta,
		ZipData:  zipData,
	}
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if !strings.Contains(string(data), want) {
		t.Fatalf("%s does not contain %q:\n%s", path, want, string(data))
	}
}

func readOpenCodeConfigForTest(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	return config
}

func containsAnyString(items []any, want string) bool {
	for _, item := range items {
		if s, ok := item.(string); ok && s == want {
			return true
		}
	}
	return false
}
