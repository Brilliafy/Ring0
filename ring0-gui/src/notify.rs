pub struct Notification {
    pub summary: String,
    pub body: String,
    pub urgency: u8,
    pub actions: Vec<(String, String)>,
}

pub struct DbusNotifier {
    _conn: Option<zbus::Connection>,
}

impl DbusNotifier {
    pub fn new() -> Self {
        Self { _conn: None }
    }

    pub async fn connect(
        &mut self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        match zbus::Connection::session().await {
            Ok(conn) => {
                self._conn = Some(conn);
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
