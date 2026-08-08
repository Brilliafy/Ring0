import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// DNS & Security view. Shows live fast-path DPI matches and the daemon's
// blocked-domain count (from the status broadcast), plus recent DPI events
// surfaced by the daemon's kernel fast path.
Rectangle {
    id: dnsRoot
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    property int blockedDomains: 0
    property int blockedCidrs: 0
    property int blockedPorts: 0
    property var dpiModel: ListModel {}

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 6

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Rectangle {
                color: "#0d1117"
                radius: 4
                Layout.fillWidth: true
                Layout.preferredHeight: 56
                border.color: "#30363d"
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Blocked Domains"; color: "#8b949e"; font.pixelSize: 10 }
                    Label { text: dnsRoot.blockedDomains; color: "#d2a8ff"; font.pixelSize: 18; font.bold: true }
                }
            }
            Rectangle {
                color: "#0d1117"
                radius: 4
                Layout.fillWidth: true
                Layout.preferredHeight: 56
                border.color: "#30363d"
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Blocked CIDRs"; color: "#8b949e"; font.pixelSize: 10 }
                    Label { text: dnsRoot.blockedCidrs; color: "#58a6ff"; font.pixelSize: 18; font.bold: true }
                }
            }
            Rectangle {
                color: "#0d1117"
                radius: 4
                Layout.fillWidth: true
                Layout.preferredHeight: 56
                border.color: "#30363d"
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Blocked Ports"; color: "#8b949e"; font.pixelSize: 10 }
                    Label { text: dnsRoot.blockedPorts; color: "#f0883e"; font.pixelSize: 18; font.bold: true }
                }
            }
        }

        Label { text: "Fast-path DPI matches (kernel)"; color: "#58a6ff"; font.pixelSize: 12; font.bold: true }

        ListView {
            id: dpiList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: dnsRoot.dpiModel
            delegate: Rectangle {
                width: parent.width
                height: 22
                color: index % 2 === 0 ? "#161b22" : "#0d1117"
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Label { text: ts; color: "#8b949e"; font.pixelSize: 10; Layout.preferredWidth: 110 }
                    Label { text: rule; color: "#f85149"; font.pixelSize: 10; Layout.preferredWidth: 50 }
                    Label { text: msg; color: "#c9d1d9"; font.pixelSize: 10; Layout.fillWidth: true; elide: Text.ElideRight }
                }
            }
        }
    }

    // Append a DPI match event.
    function addDpiMatch(rule, msg) {
        dnsRoot.dpiModel.insert(0, {
            ts: new Date().toLocaleTimeString(),
            rule: rule,
            msg: msg
        })
        if (dnsRoot.dpiModel.count > 200) {
            dnsRoot.dpiModel.remove(200, dnsRoot.dpiModel.count - 200)
        }
    }
}
