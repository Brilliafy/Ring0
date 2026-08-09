#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QtQml>
#include "ring0-gui/src/lib.cxxqt.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;

    qmlRegisterType<ring0::Ring0Bridge>("ring0", 1, 0, "Ring0Bridge");

    // Expose the design-system Theme (components/Theme.qml) as a context
    // property so every view resolves Theme.* tokens (dark/light/system).
    QQmlComponent themeComp(&engine, QUrl(QStringLiteral("qrc:/qml/components/Theme.qml")));
    QObject *themeObj = nullptr;
    if (themeComp.isError()) {
        qWarning() << "Theme.qml load error:" << themeComp.errorString();
    } else {
        themeObj = themeComp.create();
        if (!themeObj) {
            qWarning() << "Theme.qml create failed:" << themeComp.errorString();
        } else {
            engine.rootContext()->setContextProperty("Theme", themeObj);
        }
    }

    ring0::Ring0Bridge *bridge = new ring0::Ring0Bridge(&app);
    engine.rootContext()->setContextProperty("bridge", bridge);

    const char *socketEnv = qgetenv("RING0_SOCKET");
    const QString daemonSocket =
        (socketEnv && *socketEnv) ? QString::fromUtf8(socketEnv) : QStringLiteral("/run/ring0d.sock");
    engine.rootContext()->setContextProperty("daemonSocket", daemonSocket);

    engine.load(QUrl(QStringLiteral("qrc:/qml/main.qml")));

    return app.exec();
}
