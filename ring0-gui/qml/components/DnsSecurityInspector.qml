import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// DNS & Security view. Shows live fast-path DPI matches and the daemon's
// blocked-domain count (from the status broadcast), plus recent DPI events
// surfaced by the daemon's kernel fast path.
Rectangle {
    id: dnsRoot
    color: Theme.bgSurface
    radius: 6
    border.color: Theme.borderDefault
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
                color: Theme.bgBase
                radius: 4
                Layout.fillWidth: true
                Layout.preferredHeight: 56
                border.color: Theme.borderDefault
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Blocked Domains"; color: Theme.textSecondary; font.pixelSize: 10 }
                    Label { text: dnsRoot.blockedDomains; color: Theme.accentPurple; font.pixelSize: 18; font.bold: true }
                }
            }
            Rectangle {
                color: Theme.bgBase
                radius: 4
                Layout.fillWidth: true
                Layout.preferredHeight: 56
                border.color: Theme.borderDefault
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Blocked CIDRs"; color: Theme.textSecondary; font.pixelSize: 10 }
                    Label { text: dnsRoot.blockedCidrs; color: Theme.accentInfo; font.pixelSize: 18; font.bold: true }
                }
            }
            Rectangle {
                color: Theme.bgBase
                radius: 4
                Layout.fillWidth: true
                Layout.preferredHeight: 56
                border.color: Theme.borderDefault
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Blocked Ports"; color: Theme.textSecondary; font.pixelSize: 10 }
                    Label { text: dnsRoot.blockedPorts; color: Theme.accentWarning; font.pixelSize: 18; font.bold: true }
                }
            }
        }

        Label { text: "Fast-path DPI matches (kernel)"; color: Theme.accentInfo; font.pixelSize: 12; font.bold: true }

        ListView {
            id: dpiList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: dnsRoot.dpiModel
            delegate: Rectangle {
                width: parent.width
                height: 22
                color: index % 2 === 0 ? Theme.bgSurface : Theme.bgBase
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Label { text: ts; color: Theme.textSecondary; font.pixelSize: 10; Layout.preferredWidth: 110 }
                    Label { text: rule; color: Theme.accentDanger; font.pixelSize: 10; Layout.preferredWidth: 50 }
                    Label { text: msg; color: Theme.textPrimary; font.pixelSize: 10; Layout.fillWidth: true; elide: Text.ElideRight }
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
