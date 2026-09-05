#![windows_subsystem = "windows"]

use iced::application;
use hostsight::{
    utils::{self, error_dialog},
    HostSight,
};

fn main() {
    if let Err(e) = try_main() {
        error_dialog(e);
    }
}

fn try_main() -> anyhow::Result<()> {
    application("HostSight", HostSight::update, HostSight::view)
        .settings(utils::settings())
        .window(utils::window_settings())
        .theme(HostSight::theme)
        .run()?;
    Ok(())
}
