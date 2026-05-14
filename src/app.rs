use anyhow::{Context, Result};

use crate::ports::{self, PortKey, PortProcess};

pub struct App {
    pub items: Vec<PortProcess>,
    pub selected: usize,
    pub status: String,
    pub confirm_kill: Option<PortKey>,
    pub current_user: String,
}

impl App {
    pub fn load() -> Result<Self> {
        let current_user = ports::current_user().context("could not determine current user")?;
        let mut app = Self {
            items: Vec::new(),
            selected: 0,
            status: String::new(),
            confirm_kill: None,
            current_user,
        };
        app.refresh();
        Ok(app)
    }

    pub fn refresh(&mut self) {
        let previous_key = self.selected_item().map(PortProcess::key);

        match ports::list_tcp_listeners_for_user(&self.current_user) {
            Ok(items) => {
                self.items = items;
                self.restore_selection(previous_key);
                self.status = format!(
                    "Showing {} code TCP listener{} owned by {}. q quits, r refreshes, K kills.",
                    self.items.len(),
                    if self.items.len() == 1 { "" } else { "s" },
                    self.current_user
                );
            }
            Err(error) => {
                self.items.clear();
                self.selected = 0;
                self.status = format!("Could not scan ports: {error:#}");
            }
        }
        self.confirm_kill = None;
    }

    pub fn selected_item(&self) -> Option<&PortProcess> {
        self.items.get(self.selected)
    }

    pub fn select_next(&mut self) {
        self.confirm_kill = None;
        if !self.items.is_empty() {
            self.selected = (self.selected + 1).min(self.items.len() - 1);
        }
    }

    pub fn select_previous(&mut self) {
        self.confirm_kill = None;
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn request_or_confirm_kill(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            self.status = "Nothing selected.".to_string();
            self.confirm_kill = None;
            return;
        };

        let key = item.key();
        if self.confirm_kill.as_ref() != Some(&key) {
            self.status = format!(
                "Press K again to send SIGTERM to PID {} ({}) on {}:{}.",
                item.pid, item.command, item.address, item.port
            );
            self.confirm_kill = Some(key);
            return;
        }

        match ports::list_tcp_listeners_for_user(&self.current_user) {
            Ok(latest) => {
                if !latest.iter().any(|candidate| candidate.key() == key) {
                    self.items = latest;
                    self.restore_selection(Some(key));
                    self.status = "Selected process no longer owns that port.".to_string();
                    self.confirm_kill = None;
                    return;
                }
            }
            Err(error) => {
                self.status = format!("Could not recheck selected process: {error:#}");
                self.confirm_kill = None;
                return;
            }
        }

        match ports::terminate_process(item.pid) {
            Ok(()) => {
                std::thread::sleep(std::time::Duration::from_millis(150));
                let killed_pid = item.pid;
                let killed_command = item.command.clone();
                self.refresh();
                self.status = format!("Sent SIGTERM to PID {killed_pid} ({killed_command}).");
            }
            Err(error) => {
                self.status = format!("Could not kill PID {}: {error}", item.pid);
                self.confirm_kill = None;
            }
        }
    }

    pub fn cancel_confirmation(&mut self) {
        if self.confirm_kill.is_some() {
            self.confirm_kill = None;
            self.status = "Kill cancelled.".to_string();
        }
    }

    fn restore_selection(&mut self, previous_key: Option<PortKey>) {
        if self.items.is_empty() {
            self.selected = 0;
            return;
        }

        if let Some(previous_key) = previous_key {
            if let Some(index) = self
                .items
                .iter()
                .position(|item| item.key() == previous_key)
            {
                self.selected = index;
                return;
            }
        }

        self.selected = self.selected.min(self.items.len() - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, port: u16) -> PortProcess {
        PortProcess {
            pid,
            owner: "theo".to_string(),
            command: "node".to_string(),
            args: "node server.js".to_string(),
            cwd: "/Users/theo/project".to_string(),
            address: "*".to_string(),
            port,
        }
    }

    #[test]
    fn select_next_and_previous_clamp() {
        let mut app = App {
            items: vec![process(1, 3000), process(2, 3001)],
            selected: 0,
            status: String::new(),
            confirm_kill: None,
            current_user: "theo".to_string(),
        };

        app.select_previous();
        assert_eq!(app.selected, 0);

        app.select_next();
        app.select_next();
        assert_eq!(app.selected, 1);
    }
}
