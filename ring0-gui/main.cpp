#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QtQml>
#include "ring0-gui/src/lib.cxxqt.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    // Required by QSettings (Qt.labs.settings in Theme.qml): without these the
    // Settings object fails to initialize, Theme.qml fails to create and every
    // Theme.* token resolves undefined.
    QCoreApplication::setOrganizationName(QStringLiteral("RingZero"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("ring0.local"));
    QQmlApplicationEngine engine;

    qmlRegisterType<ring0::Ring0Bridge>("ring0", 1, 0, "Ring0Bridge");

    // Expose the design-system Theme (components/Theme.qml) as a context
    // property so every view resolves Theme.* tokens (dark/light/system).
    QQmlComponent themeComp(&engine, QUrl(QStringLiteral("qrc:/qml/components/Theme.qml")));
    if (themeComp.isError()) {
        qFatal("Theme.qml load error: %s", qPrintable(themeComp.errorString()));
    }
    QObject *themeObj = themeComp.create();
    if (!themeObj) {
        qFatal("Theme.qml create failed: %s", qPrintable(themeComp.errorString()));
    }
    engine.rootContext()->setContextProperty("Theme", themeObj);

    ring0::Ring0Bridge *bridge = new ring0::Ring0Bridge(&app);
    engine.rootContext()->setContextProperty("bridge", bridge);

    const char *socketEnv = qgetenv("RING0_SOCKET");
    const QString daemonSocket =
        (socketEnv && *socketEnv) ? QString::fromUtf8(socketEnv) : QStringLiteral("/run/ring0d.sock");
    engine.rootContext()->setContextProperty("daemonSocket", daemonSocket);

    engine.load(QUrl(QStringLiteral("qrc:/qml/main.qml")));

    return app.exec();
}
