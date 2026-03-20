package auth

import "strings"

// Plan levels ordered by tier.
const (
	PlanFree       = "free"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

// PlanLevel returns a numeric tier for comparison.
func PlanLevel(plan string) int {
	switch strings.ToLower(plan) {
	case PlanEnterprise, "ultra", "mega":
		return 3
	case PlanPro:
		return 2
	case PlanFree, "basic", "":
		return 1
	default:
		return 1
	}
}

// RequiresPro returns true if the plan is at least Pro.
func RequiresPro(plan string) bool {
	return PlanLevel(plan) >= 2
}

// RequiresEnterprise returns true if the plan is Enterprise.
func RequiresEnterprise(plan string) bool {
	return PlanLevel(plan) >= 3
}

// ToolAllowed checks if a tool is allowed for the given plan.
func ToolAllowed(toolName, plan string) (bool, string) {
	switch toolName {
	case "suggest_fixes":
		if !RequiresPro(plan) {
			return false, "AI-powered fix suggestions require a Pro or Enterprise plan. " +
				"Upgrade at https://mcpize.com/mcp/mcp-sct to unlock this feature."
		}
	case "generate_report":
		// SARIF format requires Pro, markdown/json are free
		// (checked at handler level for format param)
	case "run_security_test":
		if !RequiresPro(plan) {
			return false, "External security tool integration requires a Pro or Enterprise plan. " +
				"Upgrade at https://mcpize.com/mcp/mcp-sct to unlock this feature."
		}
	}
	return true, ""
}
