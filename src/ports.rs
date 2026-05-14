use std::collections::{HashMap, HashSet};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortProcess {
    pub pid: u32,
    pub owner: String,
    pub command: String,
    pub args: String,
    pub cwd: String,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortKey {
    pid: u32,
    address: String,
    port: u16,
}

impl PortProcess {
    pub fn key(&self) -> PortKey {
        PortKey {
            pid: self.pid,
            address: self.address.clone(),
            port: self.port,
        }
    }

    pub fn display_command(&self) -> &str {
        if self.args.is_empty() {
            &self.command
        } else {
            &self.args
        }
    }
}

#[derive(Default)]
struct ProcessFields {
    pid: Option<u32>,
    command: String,
    owner: String,
}

pub fn current_user() -> Result<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("USER/LOGNAME is not set"))
}

pub fn list_tcp_listeners_for_user(user: &str) -> Result<Vec<PortProcess>> {
    let output = Command::new("lsof")
        .args(["-a", "-u", user, "-nP", "-iTCP", "-sTCP:LISTEN", "-F0pcLn"])
        .output()
        .context("failed to run lsof; install lsof or make sure it is on PATH")?;

    if !output.status.success() && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Ok(Vec::new());
        }
        bail!("lsof failed: {stderr}");
    }

    let mut items = parse_lsof_fields(&output.stdout);
    let args = process_args(items.iter().map(|item| item.pid));
    let cwds = process_cwds(items.iter().map(|item| item.pid));
    for item in &mut items {
        if let Some(command_line) = args.get(&item.pid) {
            item.args.clone_from(command_line);
        }
        if let Some(cwd) = cwds.get(&item.pid) {
            item.cwd.clone_from(cwd);
        }
    }
    items.retain(is_code_process);

    items.sort_by(|left, right| {
        left.port
            .cmp(&right.port)
            .then_with(|| left.command.cmp(&right.command))
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.address.cmp(&right.address))
    });
    Ok(items)
}

pub fn parse_lsof_fields(raw: &[u8]) -> Vec<PortProcess> {
    let mut current = ProcessFields::default();
    let mut items = Vec::new();
    let mut seen = HashSet::new();

    for token in raw.split(|byte| *byte == 0) {
        let token = trim_newlines(token);
        if token.is_empty() {
            continue;
        }

        let Some((&field, value)) = token.split_first() else {
            continue;
        };
        let value = String::from_utf8_lossy(value).trim().to_string();

        match field as char {
            'p' => {
                current = ProcessFields {
                    pid: value.parse::<u32>().ok(),
                    command: String::new(),
                    owner: String::new(),
                };
            }
            'c' => current.command = value,
            'L' => current.owner = value,
            'n' => {
                let Some(pid) = current.pid else {
                    continue;
                };
                let Some((address, port)) = parse_tcp_endpoint(&value) else {
                    continue;
                };
                let key = PortKey {
                    pid,
                    address: address.clone(),
                    port,
                };
                if seen.insert(key) {
                    items.push(PortProcess {
                        pid,
                        owner: if current.owner.is_empty() {
                            "unknown".to_string()
                        } else {
                            current.owner.clone()
                        },
                        command: if current.command.is_empty() {
                            "unknown".to_string()
                        } else {
                            current.command.clone()
                        },
                        args: String::new(),
                        cwd: String::new(),
                        address,
                        port,
                    });
                }
            }
            _ => {}
        }
    }

    items
}

pub fn terminate_process(pid: u32) -> Result<()> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| format!("SIGTERM failed for {pid}"))
    }
}

fn parse_tcp_endpoint(value: &str) -> Option<(String, u16)> {
    let endpoint = value
        .split_once("->")
        .map_or(value, |(local, _)| local)
        .trim()
        .trim_end_matches(" (LISTEN)");

    let (address, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let address = match address.trim() {
        "" => "*",
        value => value,
    };
    Some((address.to_string(), port))
}

fn process_args(pids: impl Iterator<Item = u32>) -> HashMap<u32, String> {
    let mut unique_pids = pids.collect::<HashSet<_>>().into_iter().collect::<Vec<_>>();
    unique_pids.sort_unstable();
    if unique_pids.is_empty() {
        return HashMap::new();
    }

    let pid_list = unique_pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let Ok(output) = Command::new("ps")
        .args(["-p", &pid_list, "-o", "pid=", "-o", "command="])
        .output()
    else {
        return HashMap::new();
    };

    if !output.status.success() {
        return HashMap::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_ps_line)
        .collect()
}

fn process_cwds(pids: impl Iterator<Item = u32>) -> HashMap<u32, String> {
    let mut unique_pids = pids.collect::<HashSet<_>>().into_iter().collect::<Vec<_>>();
    unique_pids.sort_unstable();

    unique_pids
        .into_iter()
        .filter_map(|pid| {
            let output = Command::new("lsof")
                .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-F0pn"])
                .output()
                .ok()?;

            if !output.status.success() {
                return None;
            }

            parse_lsof_cwd(&output.stdout).map(|cwd| (pid, cwd))
        })
        .collect()
}

fn parse_lsof_cwd(raw: &[u8]) -> Option<String> {
    raw.split(|byte| *byte == 0).find_map(|token| {
        let token = trim_newlines(token);
        if token.first() == Some(&b'n') {
            Some(String::from_utf8_lossy(&token[1..]).trim().to_string())
                .filter(|value| !value.is_empty())
        } else {
            None
        }
    })
}

fn is_code_process(process: &PortProcess) -> bool {
    let command = process.command.to_lowercase();
    let args = process.args.to_lowercase();
    let cwd = process.cwd.to_lowercase();
    let haystack = format!("{command} {args} {cwd}");

    let known_code_command = matches!(
        command.as_str(),
        "node"
            | "bun"
            | "deno"
            | "python"
            | "python3"
            | "ruby"
            | "rails"
            | "puma"
            | "cargo"
            | "go"
            | "java"
            | "php"
            | "uvicorn"
            | "gunicorn"
            | "vite"
            | "next"
            | "webpack"
            | "npm"
            | "pnpm"
            | "yarn"
    );

    known_code_command
        || [
            "node_modules",
            "target/debug",
            "cargo run",
            "go run",
            "uvicorn",
            "flask",
            "django",
            "vite",
            "next",
            "webpack",
            "rails",
            "gradle",
            "mvn",
        ]
        .iter()
        .any(|marker| haystack.contains(marker))
        || is_user_project_cwd(&process.cwd)
}

fn is_user_project_cwd(cwd: &str) -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return false;
    };
    let cwd = cwd.trim();
    let home = home.trim_end_matches('/');

    cwd.starts_with(&format!("{home}/"))
        && cwd != home
        && !cwd.starts_with(&format!("{home}/Library"))
        && !cwd.starts_with(&format!("{home}/Applications"))
}

fn parse_ps_line(line: &str) -> Option<(u32, String)> {
    let line = line.trim_start();
    let mut parts = line.splitn(2, char::is_whitespace);
    let pid = parts.next()?.parse::<u32>().ok()?;
    let args = parts.next().unwrap_or_default().trim().to_string();
    Some((pid, args))
}

fn trim_newlines(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b'\n' | b'\r')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b'\n' | b'\r')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_deduplicates_macos_lsof_field_output() {
        let raw = b"p123\0cnode\0Ltheo\0\nf16\0n*:5173\0\nf17\0n*:5173\0\np456\0cGoogle Chrome Helper\0Ltheo\0\nf9\0n[::1]:3000\0\n";

        let items = parse_lsof_fields(raw);

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].pid, 123);
        assert_eq!(items[0].command, "node");
        assert_eq!(items[0].address, "*");
        assert_eq!(items[0].port, 5173);
        assert_eq!(items[1].command, "Google Chrome Helper");
        assert_eq!(items[1].address, "[::1]");
        assert_eq!(items[1].port, 3000);
    }

    #[test]
    fn ignores_non_numeric_ports_and_malformed_rows() {
        let raw = b"p1\0cidentityservicesd\0Ltheo\0\nf7\0n*:*\0\nf8\0nnot-an-endpoint\0\n";

        assert!(parse_lsof_fields(raw).is_empty());
    }

    #[test]
    fn parses_ps_output_with_command_arguments() {
        let parsed = parse_ps_line(" 84716 /opt/homebrew/bin/node ./node_modules/.bin/vite --host");

        assert_eq!(
            parsed,
            Some((
                84716,
                "/opt/homebrew/bin/node ./node_modules/.bin/vite --host".to_string()
            ))
        );
    }

    #[test]
    fn parses_lsof_cwd_field_output() {
        let raw = b"p84716\0\nfcwd\0n/Users/theo/Documents/coding/app\0\n";

        assert_eq!(
            parse_lsof_cwd(raw),
            Some("/Users/theo/Documents/coding/app".to_string())
        );
    }

    #[test]
    fn classifies_dev_processes_without_system_services() {
        let node = PortProcess {
            pid: 10,
            owner: "theo".to_string(),
            command: "node".to_string(),
            args: "node ./node_modules/.bin/vite".to_string(),
            cwd: "/Users/theo/Documents/coding/app".to_string(),
            address: "*".to_string(),
            port: 5173,
        };
        let system = PortProcess {
            pid: 11,
            owner: "theo".to_string(),
            command: "ControlCenter".to_string(),
            args: "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"
                .to_string(),
            cwd: "/".to_string(),
            address: "*".to_string(),
            port: 5000,
        };

        assert!(is_code_process(&node));
        assert!(!is_code_process(&system));
    }
}
