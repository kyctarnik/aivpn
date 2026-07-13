mod app;
mod key_storage;
mod settings;
mod tray;
mod vpn_manager;

use app::App;
use iced::{Settings, Size};

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("aivpn_linux=debug".parse().unwrap()),
        )
        .init();

    iced::application("AIVPN", App::update, App::view)
        .subscription(App::subscription)
        .theme(App::theme)
        .window(iced::window::Settings {
            size: Size::new(480.0, 420.0),
            min_size: Some(Size::new(480.0, 420.0)),
            ..Default::default()
        })
        .settings(Settings {
            antialiasing: true,
            ..Default::default()
        })
        .run_with(App::new)
}
