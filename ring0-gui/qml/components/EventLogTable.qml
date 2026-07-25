import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    property var packetModel: ListModel {}

    ListView {
        id: packetListView
        anchors.fill: parent
        anchors.margins: 4
        clip: true
        model: packetModel
        delegate: Rectangle {
            width: parent.width
            height: 22
            color: index % 2 === 0 ? "#161b22" : "#0d1117"
            RowLayout {
                anchors.fill: parent
                anchors.margins: 2
                spacing: 6
                Label { text: timestamp; color: "#8b949e"; font.pixelSize: 10; Layout.preferredWidth: 120 }
                Label { text: src; color: "#58a6ff"; font.pixelSize: 10; Layout.preferredWidth: 100 }
                Label { text: dst; color: "#58a6ff"; font.pixelSize: 10; Layout.preferredWidth: 100 }
                Label { text: proto; color: "#d2a8ff"; font.pixelSize: 10; Layout.preferredWidth: 35 }
                Label { text: pid; color: "#c9d1d9"; font.pixelSize: 10; Layout.preferredWidth: 40 }
                Label { text: action; color: action === "DROP" ? "#f85149" : "#3fb950"; font.pixelSize: 10; Layout.fillWidth: true }
            }
        }
        footer: Rectangle {
            width: parent.width; height: 2; color: "#30363d"
        }
    }

    function appendPacket(ts, src, dst, proto, pid, act) {
        if (packetModel.count > 1000) {
            packetModel.remove(1000, packetModel.count - 1000);
        }
        packetModel.insert(0, {
            timestamp: ts,
            src: src,
            dst: dst,
            proto: proto,
            pid: pid,
            action: act
        });
    }
}
