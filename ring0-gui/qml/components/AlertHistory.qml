import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Alert history: daemon-persisted alerts (bridge.queryLogs) merged with live
// alert/correlation events. Severity-colored with a Block-IP action.
Rectangle {
    id: root
    color: Theme.bgSurface
    radius: 6
    border.color: Theme.borderDefault
    border.width: 1

    property var alertModel: ListModel {}

    function sevColor(sev) {
        switch (sev) {
        case "CRITICAL": return Theme.accentDanger
        case "HIGH": return Theme.accentWarning
        case "MED": case "MEDIUM": return Theme.accentWarning
        default: return Theme.textSecondary
        }
    }

    function addAlert(sev, rule, sig, ip) {
        if (alertModel.count > 600) {
            alertModel.remove(600, alertModel.count - 600)
        }
        alertModel.insert(0, {
            ts: new Date().toLocaleTimeString(),
            sev: sev || "LOW", rule: rule || "", sig: sig || "", ip: ip || "",
            color: sevColor(sev)
        })
    }

    // Load persisted history via queryLogs (fire-and-forget; collect() picks
    // the response up on the poll timer).
    function loadHistory() {
        if (!bridge || !bridge.isConnected()) return
        bridge.queryLogs(120, 0, 500)
    }

    function collect() {
        var json = bridge.takeQuery()
        if (json.length === 0) return
        try {
            var data = JSON.parse(json)
            var alerts = data.alerts || []
            for (var i = alerts.length - 1; i >= 0; i--) {
                var a = alerts[i]
                root.addAlert(a.severity, "Rule " + a.rule_id, a.signature, "")
            }
        } catch (e) {}
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 6
        spacing: 4

        RowLayout {
            Layout.fillWidth: true
            Label { text: "Alerts (" + alertModel.count + ")"; color: Theme.accentDanger; font.pixelSize: 12; font.bold: true }
            Item { Layout.fillWidth: true }
            Button {
                text: "Load History"
                flat: true
                font.pixelSize: 10
                onClicked: root.loadHistory()
            }
        }

        ListView {
            id: alertList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: root.alertModel
            delegate: Rectangle {
                width: parent.width
                height: 24
                color: index % 2 === 0 ? Theme.bgSurface : Theme.bgBase
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Rectangle {
                        width: 64; height: 12; radius: 3
                        Layout.preferredWidth: 64
                        color: color
                        clip: true
                        Layout.alignment: Qt.AlignVCenter
                        Label { anchors.left: parent.left; anchors.leftMargin: 3; anchors.verticalCenter: parent.verticalCenter; text: sev; color: Theme.textOnAccent; font.pixelSize: 8; font.bold: true; elide: Text.ElideRight }
                    }
                    Label { text: ts; color: Theme.textSecondary; font.pixelSize: 10; Layout.preferredWidth: 80 }
                    Label { text: rule; color: Theme.accentInfo; font.pixelSize: 10; Layout.preferredWidth: 90 }
                    Label { text: sig; color: Theme.textPrimary; font.pixelSize: 10; Layout.fillWidth: true; elide: Text.ElideRight }
                    Button {
                        text: "Block"
                        flat: true
                        font.pixelSize: 9
                        implicitHeight: 18
                        visible: ip.length > 0
                        onClicked: bridge.blockIp(ip)
                    }
                }
            }
        }
    }
}
