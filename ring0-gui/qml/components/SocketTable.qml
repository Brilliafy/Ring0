import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Active TCP/UDP sockets from the daemon's /proc/net snapshot
// (bridge.listSockets): local/remote endpoints, protocol, state, owning pid.
Rectangle {
    id: root
    color: Theme.bgSurface
    radius: 6
    border.color: Theme.borderDefault
    border.width: 1

    property var socketModel: ListModel {}

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 6
        spacing: 4

        RowLayout {
            Layout.fillWidth: true
            Label { text: "Active Sockets (" + socketModel.count + ")"; color: Theme.accentInfo; font.pixelSize: 12; font.bold: true }
            Item { Layout.fillWidth: true }
            Button {
                text: "Refresh"
                flat: true
                font.pixelSize: 10
                onClicked: root.refresh()
            }
        }

        ListView {
            id: sockList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: root.socketModel
            delegate: Rectangle {
                width: parent ? parent.width : 0
                height: 20
                color: index % 2 === 0 ? Theme.bgSurface : Theme.bgBase
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Label { text: proto; color: Theme.accentPurple; font.pixelSize: 9; Layout.preferredWidth: 38 }
                    Label { text: localIp + ":" + localPort; color: Theme.accentInfo; font.pixelSize: 10; Layout.preferredWidth: 170; elide: Text.ElideRight }
                    Label { text: "→"; color: Theme.textMuted; font.pixelSize: 10; Layout.preferredWidth: 14 }
                    Label { text: remoteIp + ":" + remotePort; color: remotePort === 0 ? Theme.textSecondary : Theme.textPrimary; font.pixelSize: 10; Layout.preferredWidth: 170; elide: Text.ElideRight }
                    Label { text: state; color: state === "LISTEN" ? Theme.accentWarning : state === "ESTABLISHED" ? Theme.accentSuccess : Theme.textSecondary; font.pixelSize: 9; Layout.preferredWidth: 76 }
                    Label { text: pid; color: Theme.accentDanger; font.pixelSize: 10; Layout.preferredWidth: 46 }
                    Label { text: binary; color: Theme.textSecondary; font.pixelSize: 9; Layout.fillWidth: true; elide: Text.ElideRight }
                }
            }
        }
    }

    function setSnapshot(json) {
        try {
            var data = JSON.parse(json)
            var socks = data.sockets || []
            socketModel.clear()
            for (var i = 0; i < socks.length; i++) {
                var s = socks[i]
                socketModel.append({
                    proto: s.proto || "", localIp: s.localIp || "0.0.0.0",
                    localPort: s.localPort || 0, remoteIp: s.remoteIp || "0.0.0.0",
                    remotePort: s.remotePort || 0, state: s.state || "",
                    pid: s.pid || 0, binary: s.binary || ""
                })
            }
        } catch (e) {}
    }

    function refresh() {
        if (bridge && bridge.isConnected()) {
            bridge.listSockets() // fire-and-forget
        }
    }

    function collect() {
        var json = bridge.takeSockets()
        if (json.length > 0) setSnapshot(json)
    }
}
