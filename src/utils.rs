use iced::{
    advanced::graphics::image::image_rs::ImageFormat,
    window::{self, Level, Position},
    Font, Pixels, Settings, Size, Task,
};
use rfd::{AsyncMessageDialog, MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};

pub const JETBRAINS_MONO_FONT: Font = Font::with_name("JetBrainsMono NF");

pub const APP_NAME: &str = "HostSight";

pub fn error_dialog(error: anyhow::Error) {
    MessageDialog::new()
        .set_buttons(MessageButtons::Ok)
        .set_description(error.to_string())
        .set_level(MessageLevel::Error)
        .set_title(APP_NAME)
        .show();
}

pub fn message_dialog(message: String, level: MessageLevel) -> Task<MessageDialogResult> {
    let dialog = AsyncMessageDialog::new()
        .set_buttons(MessageButtons::Ok)
        .set_description(message)
        .set_level(level)
        .set_title(APP_NAME)
        .show();
    Task::future(dialog)
}

pub fn settings() -> Settings {
    Settings {
        fonts: vec![include_bytes!("../assets/JetBrainsMonoNerdFont-Regular.ttf").into()],
        default_font: JETBRAINS_MONO_FONT,
        default_text_size: Pixels(13.0),
        antialiasing: true,
        ..Default::default()
    }
}

pub fn window_settings() -> window::Settings {
    let size = Size::new(1440.0, 860.0);
    let min_size = Size::new(1024.0, 640.0);

    window::Settings {
        size,
        position: Position::Centered,
        min_size: Some(min_size),
        visible: true,
        resizable: true,
        decorations: true,
        transparent: false,
        level: Level::Normal,
        icon: window::icon::from_file_data(
            include_bytes!("../logo/icon.png"),
            Some(ImageFormat::Png),
        )
        .ok(),
        exit_on_close_request: true,
        ..Default::default()
    }
}
