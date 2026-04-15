//! MCP Security Hardening — fixes inspired by IronClaw v0.20.0 audit findings.
//!
//! Key mitigations:
//! 1. Input validation on all MCP messages
//! 2. Recursion depth limit
//! 3. Context growth limit
//! 4. Tool name validation (no path traversal, no special chars)

/// Maximum recursion depth for MCP tool chains.
pub const MAX_MCP_RECURSION_DEPTH: u32 = 5;

/// Maximum number of tool results in a single MCP session.
pub const MAX_MCP_RESULTS_PER_SESSION: usize = 100;

/// Maximum size of a single MCP message body in bytes.
pub const MAX_MCP_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

/// Maximum number of concurrent MCP sessions.
pub const MAX_MCP_CONCURRENT_SESSIONS: usize = 10;

/// Validate an MCP tool name — prevent path traversal and injection.
pub fn validate_tool_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Tool name cannot be empty".to_string());
    }
    if name.len() > 128 {
        return Err("Tool name too long (max 128 chars)".to_string());
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(format!(
            "Tool name '{}' contains path traversal characters",
            name
        ));
    }
    if name.contains('\0') || name.contains('\n') || name.contains('\r') {
        return Err(format!("Tool name '{}' contains control characters", name));
    }
    // Only allow alphanumeric, dash, underscore, dot
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!("Tool name '{}' contains invalid characters", name));
    }
    Ok(())
}

/// Validate MCP message size.
pub fn validate_message_size(body: &[u8]) -> Result<(), String> {
    if body.len() > MAX_MCP_MESSAGE_SIZE {
        return Err(format!(
            "MCP message too large: {} bytes (max {})",
            body.len(),
            MAX_MCP_MESSAGE_SIZE
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tool_names() {
        assert!(validate_tool_name("my-tool").is_ok());
        assert!(validate_tool_name("skill_email_audit").is_ok());
        assert!(validate_tool_name("tool.v2").is_ok());
    }

    #[test]
    fn test_path_traversal() {
        assert!(validate_tool_name("../../../etc/passwd").is_err());
        assert!(validate_tool_name("tool/../secret").is_err());
        assert!(validate_tool_name("tool\\..\\secret").is_err());
    }

    #[test]
    fn test_control_chars() {
        assert!(validate_tool_name("tool\0name").is_err());
        assert!(validate_tool_name("tool\nname").is_err());
    }

    #[test]
    fn test_special_chars() {
        assert!(validate_tool_name("tool;rm -rf /").is_err());
        assert!(validate_tool_name("tool$(evil)").is_err());
        assert!(validate_tool_name("tool`cmd`").is_err());
    }

    #[test]
    fn test_empty_name() {
        assert!(validate_tool_name("").is_err());
    }

    #[test]
    fn test_too_long_name() {
        let long = "a".repeat(200);
        assert!(validate_tool_name(&long).is_err());
    }

    #[test]
    fn test_message_size() {
        let small = vec![0u8; 100];
        assert!(validate_message_size(&small).is_ok());

        let big = vec![0u8; MAX_MCP_MESSAGE_SIZE + 1];
        assert!(validate_message_size(&big).is_err());
    }
}
