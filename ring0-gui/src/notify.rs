use std::pin::Pin;

pub struct Notification {
    pub summary: String,
    pub body: String,
    pub urgency: u8,
    pub actions: Vec<(String, String)>,
}

pub struct DbusNotifier(pub DbusNotifierInner);

pub struct DbusNotifierInner {
    _conn: zbus::Connection,
}

impl DbusNotifier {
    pub fn new() -> Self {
        DbusNotifier(DbusNotifierInner {
            _conn: zbus::Connection::new(),
        })
    }
}

impl DbusNotifierInner {
    pub async fn connect(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        match zbus::Connection::session().await {
            Ok(conn) => {
                self._conn = conn;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    pub async fn send_notification(
        &self,
        _notif: Notification,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
