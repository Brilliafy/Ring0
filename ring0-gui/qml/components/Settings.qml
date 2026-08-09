import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Settings: every control here performs a real daemon action (polkit-gated
// where privileged). No cosmetic placeholders - the previous Slack/Syslog
// "exporters" and threshold sliders were removed because the daemon has no
// such features.
Rectangle {
    id: settingsRoot
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 14

        Label { text: "Blocking"; color: "#58a6ff"; font.pixelSize: 15; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#8b949e"
            font.pixelSize: 11
            text: "Block/unblock an IP address or port. These are privileged actions: the daemon asks polkitd, which pops your desktop authentication dialog once per session."
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            TextField {
                id: blockIpField
                placeholderText: "IP address (e.g. 10.0.0.1)"
                color: "#c9d1d9"
                placeholderTextColor: "#484f58"
                background: Rectangle { color: "#0d1117"; radius: 4; border.color: "#30363d"; border.width: 1 }
                Layout.fillWidth: true
                Layout.preferredHeight: 28
            }
            Button {
                text: "Block IP"
                highlighted: true
                onClicked: {
                    if (blockIpField.text.trim().length > 0) {
                        bridge.blockIp(blockIpField.text.trim())
                        settingsStatus.text = "Block sent"
                    }
                }
            }
            Button {
                text: "Unblock"
                flat: true
                onClicked: {
                    if (blockIpField.text.trim().length > 0) {
                        bridge.unblockIp(blockIpField.text.trim())
                        settingsStatus.text = "Unblock sent"
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Label { text: "Port:"; color: "#8b949e"; font.pixelSize: 12 }
            SpinBox {
                id: portSpin
                from: 1; to: 65535; value: 4444
                editable: true
                Layout.preferredWidth: 110
            }
            Button {
                text: "Block Port"
                highlighted: true
                onClicked: { bridge.blockPort(portSpin.value); settingsStatus.text = "Block port sent" }
            }
            Button {
                text: "Unblock Port"
                flat: true
                onClicked: { bridge.unblockPort(portSpin.value); settingsStatus.text = "Unblock port sent" }
            }
        }

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: "#30363d" }

        Label { text: "About"; color: "#58a6ff"; font.pixelSize: 15; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#8b949e"
            font.pixelSize: 11
            text: "RingZero — Linux eBPF security command center. The daemon (ring0d) must run as root; the GUI connects over /run/ring0d.sock. Detection is AUDIT by default; enforcement is opt-in (RING0_RESPONSE / RING0_DPI_ENFORCE / RING0_LSM_ENFORCE). See the README §7.5 for the threat model."
        }

        Item { Layout.fillWidth: true }
        Label {
            id: settingsStatus
            text: ""
            color: "#3fb950"
            font.pixelSize: 11
        }
    }
}
