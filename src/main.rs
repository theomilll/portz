mod app;
mod ports;
mod ui;

use anyhow::Result;

fn main() -> Result<()> {
    ui::run()
}
