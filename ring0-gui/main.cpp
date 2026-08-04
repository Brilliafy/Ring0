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

    ring0::Ring0Bridge *bridge = new ring0::Ring0Bridge(&app);
    engine.rootContext()->setContextProperty("bridge", bridge);

    const char *socketEnv = qgetenv("RING0_SOCKET");
    const QString daemonSocket =
        (socketEnv && *socketEnv) ? QString::fromUtf8(socketEnv) : QStringLiteral("/run/ring0d.sock");
    engine.rootContext()->setContextProperty("daemonSocket", daemonSocket);

    engine.load(QUrl(QStringLiteral("qrc:/qml/main.qml")));

    return app.exec();
}
