use iced::{
    widget::button::{Status, Style},
    Background, Theme,
};

pub fn selected(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border.width = 1.0;
    style.text_color = palette.success.base.color;
    style.border.color = palette.success.base.color;

    match status {
        Status::Active => {}
        Status::Hovered => {
            style.background = Some(Background::Color(palette.success.weak.color));
        }
        Status::Pressed => {
            style.background = Some(Background::Color(palette.success.strong.color));
        }
        Status::Disabled => {
            style.text_color = palette.secondary.weak.color;
            style.border.color = palette.secondary.weak.color;
        }
    }

    style
}

pub fn unselected(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border.width = 1.0;
    style.text_color = palette.primary.base.color;
    style.border.color = palette.primary.base.color;

    match status {
        Status::Active => {}
        Status::Hovered => {
            style.background = Some(Background::Color(palette.primary.weak.color));
        }
        Status::Pressed => {
            style.background = Some(Background::Color(palette.background.strong.color));
        }
        Status::Disabled => {
            style.text_color = palette.secondary.weak.color;
            style.border.color = palette.secondary.weak.color;
        }
    }

    style
}
