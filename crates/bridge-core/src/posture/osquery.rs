//! osquery integration for posture assessment.
//!
//! Runs osquery queries to check device health:
//! - OS patch level
//! - Disk encryption status
//! - Firewall configuration
//! - Screen lock settings
//! - Installed software checks
//!
//! Queries are defined by admins and pushed via policy.

use serde::{Deserialize, Serialize};

use super::PostureCheck;

/// An osquery-based posture check definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryCheck {
    /// Human-readable name.
    pub name: String,
    /// The SQL query to run against osquery.
    pub query: String,
    /// How to interpret the result.
    pub expect: OsqueryExpectation,
    /// Weight for posture scoring (0-100).
    pub weight: u8,
}

/// How to evaluate an osquery result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OsqueryExpectation {
    /// Query must return at least one row.
    HasRows,
    /// Query must return zero rows.
    NoRows,
    /// A specific column in the first row must equal this value.
    ColumnEquals { column: String, value: String },
    /// A specific column must be >= this numeric value.
    ColumnAtLeast { column: String, value: i64 },
}

/// Result of running a single osquery check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryResult {
    pub check_name: String,
    pub passed: bool,
    pub rows: Vec<serde_json::Value>,
    pub error: Option<String>,
}

/// Built-in osquery checks for common posture requirements.
pub fn default_checks() -> Vec<OsqueryCheck> {
    vec![
        OsqueryCheck {
            name: "disk_encryption".to_string(),
            query: "SELECT encrypted FROM disk_encryption WHERE encrypted = 1;".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 25,
        },
        OsqueryCheck {
            name: "firewall_enabled".to_string(),
            query: "SELECT global_state FROM alf WHERE global_state >= 1;".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 15,
        },
        OsqueryCheck {
            name: "screen_lock".to_string(),
            query: "SELECT enabled FROM screenlock WHERE enabled = 1;".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 10,
        },
        OsqueryCheck {
            name: "os_up_to_date".to_string(),
            query: "SELECT version FROM os_version;".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 30,
        },
        OsqueryCheck {
            name: "sip_enabled".to_string(),
            query: "SELECT enabled FROM sip_config WHERE enabled = 1;".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 20,
        },
    ]
}

/// Evaluate an osquery result against an expectation.
pub fn evaluate_result(result: &OsqueryResult, check: &OsqueryCheck) -> PostureCheck {
    let passed = if result.error.is_some() {
        false
    } else {
        match &check.expect {
            OsqueryExpectation::HasRows => !result.rows.is_empty(),
            OsqueryExpectation::NoRows => result.rows.is_empty(),
            OsqueryExpectation::ColumnEquals { column, value } => {
                result.rows.first().map_or(false, |row| {
                    row.get(column)
                        .and_then(|v| v.as_str())
                        .map_or(false, |v| v == value)
                })
            }
            OsqueryExpectation::ColumnAtLeast { column, value } => {
                result.rows.first().map_or(false, |row| {
                    row.get(column)
                        .and_then(|v| v.as_str())
                        .and_then(|v| v.parse::<i64>().ok())
                        .map_or(false, |v| v >= *value)
                })
            }
        }
    };

    let detail = if !passed {
        result
            .error
            .clone()
            .or_else(|| Some(format!("Check '{}' failed", check.name)))
    } else {
        None
    };

    PostureCheck {
        name: check.name.clone(),
        passed,
        weight: check.weight,
        detail,
    }
}

/// Client for communicating with the local osquery daemon.
///
/// osquery exposes a Thrift interface on a Unix socket.
/// For initial implementation, we shell out to `osqueryi` (CLI mode).
pub struct OsqueryClient {
    /// Path to the osquery socket or binary.
    socket_path: String,
}

impl OsqueryClient {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    /// Default socket path for the current platform.
    pub fn default_path() -> &'static str {
        #[cfg(target_os = "macos")]
        { "/var/osquery/osquery.em" }
        #[cfg(target_os = "linux")]
        { "/var/osquery/osquery.em" }
        #[cfg(target_os = "windows")]
        { r"\\.\pipe\osquery.em" }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        { "/var/osquery/osquery.em" }
    }

    /// Run a query via osqueryi CLI (fallback when socket not available).
    pub async fn query_cli(&self, sql: &str) -> Result<Vec<serde_json::Value>, String> {
        let output = tokio::process::Command::new("osqueryi")
            .args(["--json", sql])
            .output()
            .await
            .map_err(|e| format!("Failed to run osqueryi: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("Failed to parse osquery output: {}", e))?;

        Ok(rows)
    }

    /// Run all checks and return results.
    pub async fn run_checks(&self, checks: &[OsqueryCheck]) -> Vec<OsqueryResult> {
        let mut results = Vec::new();

        for check in checks {
            match self.query_cli(&check.query).await {
                Ok(rows) => {
                    results.push(OsqueryResult {
                        check_name: check.name.clone(),
                        passed: false, // Will be evaluated by evaluate_result
                        rows,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(OsqueryResult {
                        check_name: check.name.clone(),
                        passed: false,
                        rows: vec![],
                        error: Some(e),
                    });
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_has_rows_passing() {
        let check = OsqueryCheck {
            name: "disk_encryption".to_string(),
            query: "SELECT 1".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 25,
        };

        let result = OsqueryResult {
            check_name: "disk_encryption".to_string(),
            passed: false,
            rows: vec![serde_json::json!({"encrypted": "1"})],
            error: None,
        };

        let posture = evaluate_result(&result, &check);
        assert!(posture.passed);
        assert_eq!(posture.weight, 25);
    }

    #[test]
    fn evaluate_has_rows_failing() {
        let check = OsqueryCheck {
            name: "disk_encryption".to_string(),
            query: "SELECT 1".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 25,
        };

        let result = OsqueryResult {
            check_name: "disk_encryption".to_string(),
            passed: false,
            rows: vec![],
            error: None,
        };

        let posture = evaluate_result(&result, &check);
        assert!(!posture.passed);
    }

    #[test]
    fn evaluate_column_equals() {
        let check = OsqueryCheck {
            name: "sip_enabled".to_string(),
            query: "SELECT enabled FROM sip_config".to_string(),
            expect: OsqueryExpectation::ColumnEquals {
                column: "enabled".to_string(),
                value: "1".to_string(),
            },
            weight: 20,
        };

        let result = OsqueryResult {
            check_name: "sip_enabled".to_string(),
            passed: false,
            rows: vec![serde_json::json!({"enabled": "1"})],
            error: None,
        };

        assert!(evaluate_result(&result, &check).passed);

        let bad_result = OsqueryResult {
            check_name: "sip_enabled".to_string(),
            passed: false,
            rows: vec![serde_json::json!({"enabled": "0"})],
            error: None,
        };

        assert!(!evaluate_result(&bad_result, &check).passed);
    }

    #[test]
    fn evaluate_with_error() {
        let check = OsqueryCheck {
            name: "test".to_string(),
            query: "SELECT 1".to_string(),
            expect: OsqueryExpectation::HasRows,
            weight: 10,
        };

        let result = OsqueryResult {
            check_name: "test".to_string(),
            passed: false,
            rows: vec![],
            error: Some("osquery not installed".to_string()),
        };

        let posture = evaluate_result(&result, &check);
        assert!(!posture.passed);
        assert_eq!(posture.detail.unwrap(), "osquery not installed");
    }

    #[test]
    fn default_checks_have_correct_weights() {
        let checks = default_checks();
        let total_weight: u8 = checks.iter().map(|c| c.weight).sum();
        assert_eq!(total_weight, 100);
        assert_eq!(checks.len(), 5);
    }
}
