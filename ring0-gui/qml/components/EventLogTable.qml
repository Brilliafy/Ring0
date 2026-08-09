import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    color: Theme.bgSurface
    radius: 6
    border.color: Theme.borderDefault
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
            color: Theme.rowColor(index, false)
            RowLayout {
                anchors.fill: parent
                anchors.margins: 2
                spacing: 6
                Label { text: timestamp; color: Theme.textSecondary; font.pixelSize: 10; Layout.preferredWidth: 120 }
                Label { text: src; color: Theme.accentInfo; font.pixelSize: 10; Layout.preferredWidth: 100 }
                Label { text: dst; color: Theme.accentInfo; font.pixelSize: 10; Layout.preferredWidth: 100 }
                Label { text: proto; color: Theme.accentPurple; font.pixelSize: 10; Layout.preferredWidth: 35 }
                Label { text: pid; color: Theme.textPrimary; font.pixelSize: 10; Layout.preferredWidth: 40 }
                Label { text: action; color: action === "DROP" ? Theme.accentDanger : Theme.accentSuccess; font.pixelSize: 10; Layout.fillWidth: true }
            }
        }
        footer: Rectangle {
            width: parent.width; height: 2; color: Theme.borderDefault
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
