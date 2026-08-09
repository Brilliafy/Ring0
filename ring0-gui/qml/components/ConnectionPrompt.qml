import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

Window {
    id: promptWindow
    flags: Qt.Dialog | Qt.WindowStaysOnTopHint
    // WindowModal (not ApplicationModal): ApplicationModal blocked input to
    // EVERY window, which felt like the app froze. WindowModal only blocks the
    // main window, and the countdown keeps the decision visible.
    modality: Qt.WindowModal
    width: 520
    height: 380
    color: Theme.bgSurface
    title: "Ring0 — Connection Prompt"

    property int promptId: 0
    property string binaryPath: ""
    property string parentBinary: ""
    property int pid: 0
    property int ppid: 0
    property string dstIp: ""
    property int dstPort: 0
    property string protocol: "TCP"
    property string countryCode: "XX"
    property string countryName: "Unknown"
    property string rdnsName: ""
    property int timeoutSecs: 15
    property int remainingSecs: 15

    signal decisionMade(int promptId, string action, string scope)

    Timer {
        id: countdownTimer
        interval: 1000
        repeat: true
        running: true
        onTriggered: {
            remainingSecs -= 1
            timeoutBar.value = remainingSecs / timeoutSecs
            if (remainingSecs <= 0) {
                timer.stop()
                decisionMade(promptId, "block", "exact_ip")
                promptWindow.close()
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 10

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Rectangle {
                width: 40; height: 40; radius: 8
                color: Theme.bgSurfaceAlt
                Label {
                    anchors.centerIn: parent
                    text: "🛡"
                    font.pixelSize: 20
                }
            }
            ColumnLayout {
                spacing: 2
                Label {
                    text: "Outbound Connection Attempt"
                    color: Theme.accentDanger
                    font.pixelSize: 14
                    font.bold: true
                }
                Label {
                    text: "%1 second(s) to respond".arg(remainingSecs)
                    color: Theme.textSecondary
                    font.pixelSize: 10
                }
            }
            Item { Layout.fillWidth: true }
            Button {
                text: "✕"
                flat: true
                font.pixelSize: 12
                implicitWidth: 24
                implicitHeight: 24
                ToolTip.text: "Dismiss (allow this connection once)"
                ToolTip.visible: hovered
                onClicked: {
                    decisionMade(promptId, "allow_once", "exact_ip")
                    promptWindow.close()
                }
            }
        }

        ProgressBar {
            id: timeoutBar
            Layout.fillWidth: true
            Layout.preferredHeight: 4
            from: 0; to: 1
            value: 1
            background: Rectangle { color: Theme.borderDefault; radius: 2 }
            contentItem: Rectangle {
                radius: 2
                // Fill MUST track visualPosition - the old code left the
                // width unbounded, so the "loading bar" never moved.
                width: parent.width * timeoutBar.visualPosition
                color: remainingSecs > 5 ? Theme.accentInfo : remainingSecs > 3 ? Theme.accentWarning : Theme.accentDanger
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: Theme.borderDefault
        }

        GridLayout {
            columns: 2
            columnSpacing: 12
            rowSpacing: 6
            Layout.fillWidth: true

            Label { text: "Binary:"; color: Theme.textSecondary; font.pixelSize: 11 }
            Label { text: binaryPath; color: Theme.textPrimary; font.pixelSize: 11; font.bold: true; elide: Text.ElideRight; Layout.fillWidth: true }

            Label { text: "PID / PPID:"; color: Theme.textSecondary; font.pixelSize: 11 }
            Label { text: "%1 / %2".arg(pid).arg(ppid); color: Theme.textPrimary; font.pixelSize: 11 }

            Label { text: "Parent:"; color: Theme.textSecondary; font.pixelSize: 11 }
            Label { text: parentBinary; color: Theme.textPrimary; font.pixelSize: 11; elide: Text.ElideRight; Layout.fillWidth: true }

            Label { text: "Destination:"; color: Theme.textSecondary; font.pixelSize: 11 }
            Label { text: "%1:%2 (%3)".arg(dstIp).arg(dstPort).arg(protocol); color: Theme.accentInfo; font.pixelSize: 11; font.bold: true }

            Label { text: "GeoIP:"; color: Theme.textSecondary; font.pixelSize: 11 }
            Label { text: "%1 — %2".arg(countryCode).arg(countryName); color: Theme.accentPurple; font.pixelSize: 11 }

            Label { text: "Hostname:"; color: Theme.textSecondary; font.pixelSize: 11 }
            Label { text: rdnsName; color: Theme.textPrimary; font.pixelSize: 11; elide: Text.ElideRight; Layout.fillWidth: true }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: Theme.borderDefault
        }

        Label { text: "Rule Scope:"; color: Theme.textSecondary; font.pixelSize: 11 }
        RowLayout {
            Layout.fillWidth: true
            spacing: 6
            ComboBox {
                id: scopeCombo
                model: ["Exact IP", "Domain", "Port", "Process"]
                Layout.fillWidth: true
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Button {
                text: "Allow Once"
                highlighted: true
                Layout.fillWidth: true
                onClicked: {
                    decisionMade(promptId, "allow_once", scopeCombo.currentText.toLowerCase().replace(' ', '_'))
                    promptWindow.close()
                }
            }
            Button {
                text: "Allow Always"
                highlighted: true
                Layout.fillWidth: true
                onClicked: {
                    decisionMade(promptId, "allow_always", scopeCombo.currentText.toLowerCase().replace(' ', '_'))
                    promptWindow.close()
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Button {
                text: "Block"
                Layout.fillWidth: true
                onClicked: {
                    decisionMade(promptId, "block", scopeCombo.currentText.toLowerCase().replace(' ', '_'))
                    promptWindow.close()
                }
            }
            Button {
                text: "Block Always"
                Layout.fillWidth: true
                onClicked: {
                    decisionMade(promptId, "block_always", scopeCombo.currentText.toLowerCase().replace(' ', '_'))
                    promptWindow.close()
                }
            }
        }
    }

    onDecisionMade: {
        countdownTimer.stop()
    }

    Component.onCompleted: {
        remainingSecs = timeoutSecs
        x = Screen.width / 2 - width / 2
        y = Screen.height / 2 - height / 2
    }
}
