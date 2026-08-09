import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Active TCP/UDP sockets from the daemon's /proc/net snapshot
// (bridge.listSockets): local/remote endpoints, protocol, state, owning pid.
Rectangle {
    id: root
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    property var socketModel: ListModel {}

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 6
        spacing: 4

        RowLayout {
            Layout.fillWidth: true
            Label { text: "Active Sockets (" + socketModel.count + ")"; color: "#58a6ff"; font.pixelSize: 12; font.bold: true }
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
                width: parent.width
                height: 20
                color: index % 2 === 0 ? "#161b22" : "#0d1117"
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Label { text: proto; color: "#d2a8ff"; font.pixelSize: 9; Layout.preferredWidth: 38 }
                    Label { text: localIp + ":" + localPort; color: "#58a6ff"; font.pixelSize: 10; Layout.preferredWidth: 170; elide: Text.ElideRight }
                    Label { text: "→"; color: "#484f58"; font.pixelSize: 10; Layout.preferredWidth: 14 }
                    Label { text: remoteIp + ":" + remotePort; color: remotePort === 0 ? "#8b949e" : "#c9d1d9"; font.pixelSize: 10; Layout.preferredWidth: 170; elide: Text.ElideRight }
                    Label { text: state; color: state === "LISTEN" ? "#d29922" : state === "ESTABLISHED" ? "#3fb950" : "#8b949e"; font.pixelSize: 9; Layout.preferredWidth: 76 }
                    Label { text: pid; color: "#f85149"; font.pixelSize: 10; Layout.preferredWidth: 46 }
                    Label { text: binary; color: "#8b949e"; font.pixelSize: 9; Layout.fillWidth: true; elide: Text.ElideRight }
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
            setSnapshot(bridge.listSockets())
        }
    }
}
