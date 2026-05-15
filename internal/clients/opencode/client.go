package opencode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sleuth-io/sx/internal/asset"
	"github.com/sleuth-io/sx/internal/bootstrap"
	"github.com/sleuth-io/sx/internal/clients"
	"github.com/sleuth-io/sx/internal/handlers/dirasset"
	ruleasset "github.com/sleuth-io/sx/internal/handlers/rule"
	"github.com/sleuth-io/sx/internal/lockfile"
	"github.com/sleuth-io/sx/internal/metadata"
	"github.com/sleuth-io/sx/internal/utils"
)

const (
	configDir     = ".config/opencode"
	projectDir    = ".opencode"
	configFile    = "opencode.json"
	dirSkills     = "skills"
	dirCommands   = "commands"
	dirAgents     = "agents"
	dirRules      = "rules"
	dirMCPServers = "mcp-servers"
)

var skillOps = dirasset.NewOperations(dirSkills, &asset.TypeSkill)

// Client implements the clients.Client interface for OpenCode.
type Client struct {
	clients.BaseClient
}

// NewClient creates a new OpenCode client.
func NewClient() *Client {
	return &Client{
		BaseClient: clients.NewBaseClient(
			clients.ClientIDOpenCode,
			"OpenCode",
			[]asset.Type{
				asset.TypeSkill,
				asset.TypeCommand,
				asset.TypeAgent,
				asset.TypeRule,
				asset.TypeMCP,
			},
		),
	}
}

// IsInstalled checks if OpenCode is installed by checking its config directory or binary.
func (c *Client) IsInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	if stat, err := os.Stat(filepath.Join(home, configDir)); err == nil && stat.IsDir() {
		return true
	}

	_, err = exec.LookPath("opencode")
	return err == nil
}

// GetVersion returns the OpenCode version.
func (c *Client) GetVersion() string {
	cmd := exec.Command("opencode", "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// InstallAssets installs assets to OpenCode using its file-based config layout.
func (c *Client) InstallAssets(ctx context.Context, req clients.InstallRequest) (clients.InstallResponse, error) {
	resp := clients.InstallResponse{Results: make([]clients.AssetResult, 0, len(req.Assets))}

	for _, bundle := range req.Assets {
		result := clients.AssetResult{AssetName: bundle.Asset.Name}

		targetBase, err := c.determineTargetBase(req.Scope)
		if err != nil {
			result.Status = clients.StatusFailed
			result.Error = err
			result.Message = fmt.Sprintf("Cannot determine installation directory: %v", err)
			resp.Results = append(resp.Results, result)
			continue
		}

		if err := os.MkdirAll(targetBase, 0755); err != nil {
			result.Status = clients.StatusFailed
			result.Error = err
			result.Message = fmt.Sprintf("Failed to create target directory: %v", err)
			resp.Results = append(resp.Results, result)
			continue
		}

		installErr := c.installAsset(ctx, bundle, targetBase)
		if installErr != nil {
			result.Status = clients.StatusFailed
			result.Error = installErr
			result.Message = fmt.Sprintf("Installation failed: %v", installErr)
		} else {
			result.Status = clients.StatusSuccess
			result.Message = "Installed to " + targetBase
		}

		resp.Results = append(resp.Results, result)
	}

	return resp, nil
}

// UninstallAssets removes assets from OpenCode.
func (c *Client) UninstallAssets(ctx context.Context, req clients.UninstallRequest) (clients.UninstallResponse, error) {
	resp := clients.UninstallResponse{Results: make([]clients.AssetResult, 0, len(req.Assets))}

	for _, a := range req.Assets {
		result := clients.AssetResult{AssetName: a.Name}

		targetBase, err := c.determineTargetBase(req.Scope)
		if err != nil {
			result.Status = clients.StatusFailed
			result.Error = err
			resp.Results = append(resp.Results, result)
			continue
		}

		meta := &metadata.Metadata{Asset: metadata.Asset{Name: a.Name, Type: a.Type}}
		uninstallErr := c.removeAsset(ctx, meta, targetBase)
		if uninstallErr != nil {
			result.Status = clients.StatusFailed
			result.Error = uninstallErr
		} else {
			result.Status = clients.StatusSuccess
			result.Message = "Uninstalled successfully"
		}

		resp.Results = append(resp.Results, result)
	}

	return resp, nil
}

func (c *Client) determineTargetBase(scope *clients.InstallScope) (string, error) {
	home, _ := os.UserHomeDir()
	if scope == nil {
		return filepath.Join(home, configDir), nil
	}

	switch scope.Type {
	case clients.ScopeGlobal:
		return filepath.Join(home, configDir), nil
	case clients.ScopeRepository:
		if scope.RepoRoot == "" {
			return "", errors.New("repo-scoped install requires RepoRoot but none provided (not in a git repository?)")
		}
		return filepath.Join(scope.RepoRoot, projectDir), nil
	case clients.ScopePath:
		if scope.RepoRoot == "" {
			return "", errors.New("path-scoped install requires RepoRoot but none provided (not in a git repository?)")
		}
		return filepath.Join(scope.RepoRoot, scope.Path, projectDir), nil
	default:
		return filepath.Join(home, configDir), nil
	}
}

func (c *Client) installAsset(ctx context.Context, bundle *clients.AssetBundle, targetBase string) error {
	switch bundle.Metadata.Asset.Type {
	case asset.TypeSkill:
		return installSkill(ctx, bundle, targetBase)
	case asset.TypeCommand:
		return installCommand(bundle.Metadata, bundle.ZipData, targetBase)
	case asset.TypeAgent:
		return installAgent(bundle.Metadata, bundle.ZipData, targetBase)
	case asset.TypeRule:
		return installRule(bundle.Metadata, bundle.ZipData, targetBase)
	case asset.TypeMCP:
		return installMCP(bundle.Metadata, bundle.ZipData, targetBase)
	default:
		return fmt.Errorf("unsupported asset type: %s", bundle.Metadata.Asset.Type.Key)
	}
}

func (c *Client) removeAsset(ctx context.Context, meta *metadata.Metadata, targetBase string) error {
	switch meta.Asset.Type {
	case asset.TypeSkill:
		return skillOps.Remove(ctx, targetBase, meta.Asset.Name)
	case asset.TypeCommand:
		return removeFile(filepath.Join(targetBase, dirCommands, meta.Asset.Name+".md"))
	case asset.TypeAgent:
		return removeFile(filepath.Join(targetBase, dirAgents, meta.Asset.Name+".md"))
	case asset.TypeRule:
		path := filepath.Join(targetBase, dirRules, meta.Asset.Name+".md")
		if err := removeInstruction(targetBase, filepath.ToSlash(filepath.Join(dirRules, meta.Asset.Name+".md"))); err != nil {
			return err
		}
		return removeFile(path)
	case asset.TypeMCP:
		if err := removeMCPServer(targetBase, meta.Asset.Name); err != nil {
			return err
		}
		return os.RemoveAll(filepath.Join(targetBase, dirMCPServers, meta.Asset.Name))
	default:
		return fmt.Errorf("unsupported asset type: %s", meta.Asset.Type.Key)
	}
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func installSkill(ctx context.Context, bundle *clients.AssetBundle, targetBase string) error {
	if err := skillOps.Install(ctx, bundle.ZipData, targetBase, bundle.Metadata.Asset.Name); err != nil {
		return err
	}

	skillPath := filepath.Join(targetBase, dirSkills, bundle.Metadata.Asset.Name, "SKILL.md")
	content, err := os.ReadFile(skillPath)
	if err != nil {
		return fmt.Errorf("failed to read installed SKILL.md: %w", err)
	}
	if strings.HasPrefix(strings.TrimSpace(string(content)), "---") {
		return nil
	}

	frontmatter := fmt.Sprintf("---\nname: %s\ndescription: %s\ncompatibility: opencode\n---\n\n", bundle.Metadata.Asset.Name, yamlScalar(bundle.Metadata.Asset.Description))
	return os.WriteFile(skillPath, []byte(frontmatter+string(content)), 0644)
}

func installCommand(meta *metadata.Metadata, zipData []byte, targetBase string) error {
	promptFile := ""
	if meta.Command != nil {
		promptFile = meta.Command.PromptFile
	}
	if promptFile == "" {
		return errors.New("no prompt file specified in metadata")
	}

	content, err := utils.ReadZipFile(zipData, promptFile)
	if err != nil {
		return fmt.Errorf("failed to read prompt file: %w", err)
	}

	dir := filepath.Join(targetBase, dirCommands)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	commandContent := buildFrontmatter(map[string]string{
		"description": meta.Asset.Description,
	}) + strings.TrimSpace(string(content)) + "\n"
	return os.WriteFile(filepath.Join(dir, meta.Asset.Name+".md"), []byte(commandContent), 0644)
}

func installAgent(meta *metadata.Metadata, zipData []byte, targetBase string) error {
	promptFile := "AGENT.md"
	if meta.Agent != nil && meta.Agent.PromptFile != "" {
		promptFile = meta.Agent.PromptFile
	}

	content, err := utils.ReadZipFile(zipData, promptFile)
	if err != nil {
		content, err = utils.ReadZipFile(zipData, "agent.md")
		if err != nil {
			return fmt.Errorf("prompt file not found: %s", promptFile)
		}
	}

	dir := filepath.Join(targetBase, dirAgents)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	agentContent := buildFrontmatter(map[string]string{
		"description": meta.Asset.Description,
	}) + strings.TrimSpace(string(content)) + "\n"
	return os.WriteFile(filepath.Join(dir, meta.Asset.Name+".md"), []byte(agentContent), 0644)
}

func installRule(meta *metadata.Metadata, zipData []byte, targetBase string) error {
	promptFile := ruleasset.DefaultPromptFile
	if meta.Rule != nil && meta.Rule.PromptFile != "" {
		promptFile = meta.Rule.PromptFile
	}

	content, err := utils.ReadZipFile(zipData, promptFile)
	if err != nil {
		content, err = utils.ReadZipFile(zipData, "rule.md")
		if err != nil {
			return fmt.Errorf("prompt file not found: %s", promptFile)
		}
	}

	dir := filepath.Join(targetBase, dirRules)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	title := meta.Asset.Name
	if meta.Rule != nil && meta.Rule.Title != "" {
		title = meta.Rule.Title
	}
	ruleContent := "# " + title + "\n\n" + strings.TrimSpace(string(content)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, meta.Asset.Name+".md"), []byte(ruleContent), 0644); err != nil {
		return err
	}

	return addInstruction(targetBase, filepath.ToSlash(filepath.Join(dirRules, meta.Asset.Name+".md")))
}

func installMCP(meta *metadata.Metadata, zipData []byte, targetBase string) error {
	entry, err := buildMCPEntry(meta, zipData, targetBase)
	if err != nil {
		return err
	}
	return addMCPServer(targetBase, meta.Asset.Name, entry)
}

func buildMCPEntry(meta *metadata.Metadata, zipData []byte, targetBase string) (map[string]any, error) {
	if meta.MCP == nil {
		return nil, errors.New("mcp configuration missing")
	}

	if meta.MCP.IsRemote() {
		entry := map[string]any{
			"type":    "remote",
			"url":     meta.MCP.URL,
			"enabled": true,
		}
		if meta.MCP.Timeout > 0 {
			entry["timeout"] = meta.MCP.Timeout
		}
		return entry, nil
	}

	serverDir := ""
	hasContent, err := utils.HasContentFiles(zipData)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect zip contents: %w", err)
	}
	if hasContent {
		serverDir = filepath.Join(targetBase, dirMCPServers, meta.Asset.Name)
		if err := utils.ExtractZip(zipData, serverDir); err != nil {
			return nil, fmt.Errorf("failed to extract MCP server: %w", err)
		}
	}

	command := meta.MCP.Command
	args := meta.MCP.Args
	if serverDir != "" {
		command = utils.ResolveCommand(command, serverDir)
		args = utils.ResolveArgs(args, serverDir)
	}

	entry := map[string]any{
		"type":    "local",
		"command": append([]string{command}, args...),
		"enabled": true,
	}
	if len(meta.MCP.Env) > 0 {
		entry["environment"] = meta.MCP.Env
	}
	if meta.MCP.Timeout > 0 {
		entry["timeout"] = meta.MCP.Timeout
	}
	return entry, nil
}

func buildFrontmatter(fields map[string]string) string {
	var sb strings.Builder
	sb.WriteString("---\n")
	for key, value := range fields {
		if value != "" {
			fmt.Fprintf(&sb, "%s: %s\n", key, yamlScalar(value))
		}
	}
	sb.WriteString("---\n\n")
	return sb.String()
}

func yamlScalar(value string) string {
	if value == "" {
		return "\"\""
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "\"\""
	}
	return string(data)
}

// ListAssets returns all installed skills for a given scope.
func (c *Client) ListAssets(ctx context.Context, scope *clients.InstallScope) ([]clients.InstalledSkill, error) {
	targetBase, err := c.determineTargetBase(scope)
	if err != nil {
		return nil, fmt.Errorf("cannot determine target directory: %w", err)
	}

	installed, err := skillOps.ScanInstalled(targetBase)
	if err != nil {
		return nil, fmt.Errorf("failed to scan installed skills: %w", err)
	}

	skills := make([]clients.InstalledSkill, 0, len(installed))
	for _, info := range installed {
		skills = append(skills, clients.InstalledSkill{Name: info.Name, Description: info.Description, Version: info.Version})
	}
	return skills, nil
}

// ReadSkill reads the content of a specific skill by name.
func (c *Client) ReadSkill(ctx context.Context, name string, scope *clients.InstallScope) (*clients.SkillContent, error) {
	targetBase, err := c.determineTargetBase(scope)
	if err != nil {
		return nil, fmt.Errorf("cannot determine target directory: %w", err)
	}

	result, err := skillOps.ReadPromptContent(targetBase, name, "SKILL.md", func(m *metadata.Metadata) string { return m.Skill.PromptFile })
	if err != nil {
		return nil, err
	}

	return &clients.SkillContent{Name: name, Description: result.Description, Version: result.Version, Content: result.Content, BaseDir: result.BaseDir}, nil
}

// EnsureAssetSupport is a no-op for OpenCode since it reads assets natively.
func (c *Client) EnsureAssetSupport(ctx context.Context, scope *clients.InstallScope) error {
	return nil
}

// GetBootstrapOptions returns bootstrap options for OpenCode.
func (c *Client) GetBootstrapOptions(ctx context.Context) []bootstrap.Option {
	return []bootstrap.Option{bootstrap.SleuthAIQueryMCP()}
}

// GetBootstrapPath returns the path to OpenCode's config file.
func (c *Client) GetBootstrapPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, configDir, configFile)
}

// InstallBootstrap installs OpenCode MCP bootstrap options.
func (c *Client) InstallBootstrap(ctx context.Context, opts []bootstrap.Option) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	targetBase := filepath.Join(home, configDir)

	for _, opt := range opts {
		if opt.MCPConfig == nil {
			continue
		}
		entry := map[string]any{
			"type":    "local",
			"command": append([]string{opt.MCPConfig.Command}, opt.MCPConfig.Args...),
			"enabled": true,
		}
		if len(opt.MCPConfig.Env) > 0 {
			entry["environment"] = opt.MCPConfig.Env
		}
		if err := addMCPServer(targetBase, opt.MCPConfig.Name, entry); err != nil {
			return fmt.Errorf("failed to install MCP server %s: %w", opt.MCPConfig.Name, err)
		}
	}

	return nil
}

// UninstallBootstrap removes OpenCode MCP bootstrap options.
func (c *Client) UninstallBootstrap(ctx context.Context, opts []bootstrap.Option) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	targetBase := filepath.Join(home, configDir)

	for _, opt := range opts {
		if opt.MCPConfig != nil {
			if err := removeMCPServer(targetBase, opt.MCPConfig.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// ShouldInstall always returns true for OpenCode.
func (c *Client) ShouldInstall(ctx context.Context) (bool, error) {
	return true, nil
}

// VerifyAssets checks if assets are actually installed on the filesystem.
func (c *Client) VerifyAssets(ctx context.Context, assets []*lockfile.Asset, scope *clients.InstallScope) []clients.VerifyResult {
	results := make([]clients.VerifyResult, 0, len(assets))

	for _, a := range assets {
		result := clients.VerifyResult{Asset: a}

		targetBase, err := c.determineTargetBase(scope)
		if err != nil {
			result.Installed = false
			result.Message = fmt.Sprintf("cannot determine target directory: %v", err)
			results = append(results, result)
			continue
		}

		result.Installed, result.Message = verifyInstalled(targetBase, a)
		results = append(results, result)
	}

	return results
}

func verifyInstalled(targetBase string, a *lockfile.Asset) (bool, string) {
	switch a.Type {
	case asset.TypeSkill:
		return skillOps.VerifyInstalled(targetBase, a.Name, a.Version)
	case asset.TypeCommand:
		return fileExists(filepath.Join(targetBase, dirCommands, a.Name+".md"), "command file not found")
	case asset.TypeAgent:
		return fileExists(filepath.Join(targetBase, dirAgents, a.Name+".md"), "agent file not found")
	case asset.TypeRule:
		return fileExists(filepath.Join(targetBase, dirRules, a.Name+".md"), "rule file not found")
	case asset.TypeMCP:
		return verifyMCPServer(targetBase, a.Name)
	default:
		return false, "unsupported asset type"
	}
}

func fileExists(path, missing string) (bool, string) {
	if _, err := os.Stat(path); err == nil {
		return true, "Found at " + path
	}
	return false, missing
}

// ScanInstalledAssets scans for unmanaged assets.
func (c *Client) ScanInstalledAssets(ctx context.Context, scope *clients.InstallScope) ([]clients.InstalledAsset, error) {
	return []clients.InstalledAsset{}, nil
}

// GetAssetPath returns the filesystem path to an installed asset.
func (c *Client) GetAssetPath(ctx context.Context, name string, assetType asset.Type, scope *clients.InstallScope) (string, error) {
	targetBase, err := c.determineTargetBase(scope)
	if err != nil {
		return "", fmt.Errorf("cannot determine target directory: %w", err)
	}

	switch assetType {
	case asset.TypeSkill:
		return filepath.Join(targetBase, dirSkills, name), nil
	case asset.TypeCommand:
		return filepath.Join(targetBase, dirCommands, name+".md"), nil
	case asset.TypeAgent:
		return filepath.Join(targetBase, dirAgents, name+".md"), nil
	case asset.TypeRule:
		return filepath.Join(targetBase, dirRules, name+".md"), nil
	case asset.TypeMCP:
		return filepath.Join(targetBase, configFile), nil
	default:
		return "", fmt.Errorf("path not supported for type: %s", assetType)
	}
}

// RuleCapabilities returns nil because OpenCode uses AGENTS.md/instructions rather than a dedicated rule file format.
func (c *Client) RuleCapabilities() *clients.RuleCapabilities {
	return nil
}

type openCodeConfig struct {
	MCP          map[string]any `json:"mcp,omitempty"`
	Instructions []string       `json:"instructions,omitempty"`
	Other        map[string]any `json:"-"`
}

func readConfig(targetBase string) (*openCodeConfig, error) {
	config := &openCodeConfig{
		MCP:   make(map[string]any),
		Other: make(map[string]any),
	}

	data, err := os.ReadFile(filepath.Join(targetBase, configFile))
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, err
	}

	var raw map[string]any
	if err := utils.UnmarshalJSONC(data, &raw); err != nil {
		return nil, err
	}

	if mcp, ok := raw["mcp"].(map[string]any); ok {
		config.MCP = mcp
	}
	if instructions, ok := raw["instructions"].([]any); ok {
		for _, item := range instructions {
			if s, ok := item.(string); ok {
				config.Instructions = append(config.Instructions, s)
			}
		}
	}

	for k, v := range raw {
		if k != "mcp" && k != "instructions" {
			config.Other[k] = v
		}
	}
	return config, nil
}

func writeConfig(targetBase string, config *openCodeConfig) error {
	output := make(map[string]any)
	maps.Copy(output, config.Other)
	if len(config.MCP) > 0 {
		output["mcp"] = config.MCP
	}
	if len(config.Instructions) > 0 {
		output["instructions"] = config.Instructions
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(targetBase, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(targetBase, configFile), data, 0644)
}

func addMCPServer(targetBase, name string, entry map[string]any) error {
	config, err := readConfig(targetBase)
	if err != nil {
		return err
	}
	config.MCP[name] = entry
	return writeConfig(targetBase, config)
}

func removeMCPServer(targetBase, name string) error {
	config, err := readConfig(targetBase)
	if err != nil {
		return err
	}
	delete(config.MCP, name)
	return writeConfig(targetBase, config)
}

func verifyMCPServer(targetBase, name string) (bool, string) {
	config, err := readConfig(targetBase)
	if err != nil {
		return false, "failed to read opencode.json: " + err.Error()
	}
	if _, ok := config.MCP[name]; ok {
		return true, "registered in opencode.json"
	}
	return false, "MCP server not registered"
}

func addInstruction(targetBase, instruction string) error {
	config, err := readConfig(targetBase)
	if err != nil {
		return err
	}
	if slices.Contains(config.Instructions, instruction) {
		return nil
	}
	config.Instructions = append(config.Instructions, instruction)
	return writeConfig(targetBase, config)
}

func removeInstruction(targetBase, instruction string) error {
	config, err := readConfig(targetBase)
	if err != nil {
		return err
	}
	filtered := config.Instructions[:0]
	for _, existing := range config.Instructions {
		if existing != instruction {
			filtered = append(filtered, existing)
		}
	}
	config.Instructions = filtered
	return writeConfig(targetBase, config)
}

func init() {
	clients.Register(NewClient())
}
