use std::collections::HashMap;

use zbus::proxy::Proxy;
use zbus::zvariant::Value;

pub struct Notification {
    pub summary: String,
    pub body: String,
    pub urgency: u8,
    pub actions: Vec<(String, String)>,
}

pub struct DbusNotifier {
    conn: Option<zbus::Connection>,
}

impl DbusNotifier {
    pub fn new() -> Self {
        Self { conn: None }
    }

    pub async fn connect(&mut self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        match zbus::Connection::session().await {
            Ok(conn) => {
                self.conn = Some(conn);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    pub async fn send_notification(
        &self,
        notif: Notification,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(conn) = &self.conn else {
            return Ok(());
        };
        let proxy = Proxy::new(
            conn,
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        )
        .await?;

        let app_icon = match notif.urgency {
            2 => "dialog-error",
            1 => "dialog-warning",
            _ => "dialog-information",
        };

        let mut hints = HashMap::new();
        hints.insert("urgency", Value::from(u8::from(notif.urgency)));
        hints.insert("category", Value::from("im"));

        let action_keys: Vec<&str> = notif.actions.iter().map(|(k, _)| k.as_str()).collect();
        let action_labels: Vec<&str> = notif.actions.iter().map(|(_, v)| v.as_str()).collect();
        let mut actions = Vec::new();
        for (k, l) in action_keys.into_iter().zip(action_labels.into_iter()) {
            actions.push(k);
            actions.push(l);
        }

        let _: u32 = proxy
            .call(
                "Notify",
                &(
                    "ring0",
                    0u32,       // replaces_id
                    app_icon,    // app_icon
                    notif.summary.as_str(),
                    notif.body.as_str(),
                    actions,     // actions: Vec<&str>
                    hints,       // hints: a{sv}
                    -1i32,       // timeout (default)
                ),
            )
            .await?;
        Ok(())
    }
}
