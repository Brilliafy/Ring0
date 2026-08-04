import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    Label {
        anchors.centerIn: parent
        text: "DNS & Security Inspector — waiting for daemon events"
        color: "#484f58"
    }
}
