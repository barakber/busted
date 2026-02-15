//! File access monitoring: /proc scan for AI process names and
//! reason classification for file-access events.

use std::collections::HashSet;

/// Known AI/LLM tool process names to look for in /proc.
pub const AI_PROCESS_NAMES: &[&str] = &[
    "claude", "cursor", "aider", "cody", "copilot", "continue", "windsurf", "tabby",
];

/// AI-related path patterns (for userspace reason classification).
const AI_PATH_PATTERNS: &[(&str, &str)] = &[
    (".claude", "path_pattern:.claude"),
    ("CLAUDE.md", "path_pattern:CLAUDE.md"),
    (".cursor", "path_pattern:.cursor"),
    (".env", "path_pattern:.env"),
    ("skills/", "path_pattern:skills/"),
    (".anthropic", "path_pattern:.anthropic"),
];

/// Scan /proc for processes matching known AI tool names.
/// Returns the set of PIDs whose comm matches an AI process name.
pub fn scan_ai_processes() -> HashSet<u32> {
    let mut pids = HashSet::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return pids,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Only numeric directory names are PIDs
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Read /proc/<pid>/comm
        let comm_path = format!("/proc/{}/comm", pid);
        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let comm = comm.trim();
        for &ai_name in AI_PROCESS_NAMES {
            if comm == ai_name || comm.starts_with(ai_name) {
                pids.insert(pid);
                break;
            }
        }
    }
    pids
}

/// Classify why a file-access event was interesting.
/// Returns a reason string based on PID tracking or path pattern match.
pub fn classify_reason(path: &str, pid_tracked: bool) -> Option<String> {
    if pid_tracked {
        return Some("pid_tracked".to_string());
    }
    for &(pattern, reason) in AI_PATH_PATTERNS {
        if path.contains(pattern) {
            return Some(reason.to_string());
        }
    }
    None
}
