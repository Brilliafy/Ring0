#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include "cxx-qt-gen/qobject.cxxqt.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;

    qmlRegisterType<ring0::Ring0Bridge>("ring0", 1, 0, "Ring0Bridge");
    qmlRegisterType<ring0::PacketLogModel>("ring0", 1, 0, "PacketLogModel");
    qmlRegisterType<ring0::ProcessListModel>("ring0", 1, 0, "ProcessListModel");
    qmlRegisterType<ring0::TopologyModel>("ring0", 1, 0, "TopologyModel");

    engine.load(QUrl(QStringLiteral("qrc:/qml/main.qml")));

    return app.exec();
}
