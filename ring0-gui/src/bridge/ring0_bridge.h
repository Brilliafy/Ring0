#pragma once
#include <cxx-qt/string.h>
#include <cxx-qt/signal.h>

namespace qobject {

class Ring0Bridge : public CxxQObject {
    Q_OBJECT
public:
    explicit Ring0Bridge(QObject *parent = nullptr);
    ~Ring0Bridge();

    Q_INVOKABLE bool connectDaemon(const rust::String &socket_path);
    Q_INVOKABLE void blockIp(const rust::String &ip);
    Q_INVOKABLE void killProcess(quint32 pid);
    Q_INVOKABLE rust::String pollEvents();

Q_SIGNALS:
    void onEvent(const rust::String &event_json);
    void onAlert(const rust::String &alert_json);
};

} // namespace qobject
