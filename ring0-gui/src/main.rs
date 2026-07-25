#[allow(non_snake_case)]
mod bridge;
pub mod models;
pub mod notify;
pub mod topology_model;

use cxx_qt::QObject;

#[cxx_qt::bridge]
mod qobject {
    unsafe extern "C++" {
        include!("ring0-gui/src/bridge/ring0_bridge.h");
    }

    unsafe extern "Rust" {
        #[qobject]
        type Ring0Bridge = super::bridge::Ring0BridgeRust;

        #[qsignal]
        fn onEvent(self: Pin<&mut Ring0Bridge>, event_json: String);

        #[qsignal]
        fn onAlert(self: Pin<&mut Ring0Bridge>, alert_json: String);

        #[qinvokable]
        fn connectDaemon(self: Pin<&mut Ring0Bridge>, socket_path: String) -> bool;

        #[qinvokable]
        fn blockIp(self: Pin<&mut Ring0Bridge>, ip: String);

        #[qinvokable]
        fn killProcess(self: Pin<&mut Ring0Bridge>, pid: u32);

        #[qinvokable]
        fn pollEvents(self: Pin<&mut Ring0Bridge>) -> String;

        #[qinvokable]
        fn sendDesktopNotification(
            self: Pin<&mut Ring0Bridge>,
            severity: u32,
            title: String,
            message: String,
        );

        #[qinvokable]
        fn initDbusNotifications(self: Pin<&mut Ring0Bridge>);
    }
}

fn main() {
    cxx_qt::qml_engine::init::<qobject::Ring0Bridge>(|engine| {
        let _ = engine.load_from_path("qml/main.qml");
    });
}
