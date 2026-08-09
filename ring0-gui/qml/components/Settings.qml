import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Settings: every control here performs a real daemon action (polkit-gated
// where privileged). No cosmetic placeholders - the previous Slack/Syslog
// "exporters" and threshold sliders were removed because the daemon has no
// such features.
Rectangle {
    id: settingsRoot
    color: Theme.bgSurface
    radius: 6
    border.color: Theme.borderDefault
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 14

        Label { text: "Appearance"; color: Theme.accentInfo; font.pixelSize: 15; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: Theme.textSecondary
            font.pixelSize: Theme.fontMeta
            text: "Applied instantly. \"System\" follows your desktop appearance, including live changes."
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Label { text: "Theme:"; color: Theme.textSecondary; font.pixelSize: Theme.fontBody }
            ComboBox {
                id: themeCombo
                model: ["System", "Dark", "Light"]
                currentIndex: Theme.mode === "dark" ? 1 : Theme.mode === "light" ? 2 : 0
                onActivated: {
                    Theme.setMode(index === 0 ? "system" : index === 1 ? "dark" : "light")
                    settingsStatus.text = "Theme set to " + model[index]
                }
                Layout.preferredWidth: 140
            }
        }

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.divider }

        Label { text: "Blocking"; color: Theme.accentInfo; font.pixelSize: 15; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: Theme.textSecondary
            font.pixelSize: 11
            text: "Block/unblock an IP address or port. These are privileged actions: the daemon asks polkitd, which pops your desktop authentication dialog once per session."
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            TextField {
                id: blockIpField
                placeholderText: "IP address (e.g. 10.0.0.1)"
                color: Theme.textPrimary
                placeholderTextColor: Theme.textMuted
                background: Rectangle { color: Theme.bgBase; radius: 4; border.color: Theme.borderDefault; border.width: 1 }
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
            Label { text: "Port:"; color: Theme.textSecondary; font.pixelSize: 12 }
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

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.borderDefault }

        Label { text: "About"; color: Theme.accentInfo; font.pixelSize: 15; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: Theme.textSecondary
            font.pixelSize: 11
            text: "RingZero — Linux eBPF security command center. The daemon (ring0d) must run as root; the GUI connects over /run/ring0d.sock. Detection is AUDIT by default; enforcement is opt-in (RING0_RESPONSE / RING0_DPI_ENFORCE / RING0_LSM_ENFORCE). See the README §7.5 for the threat model."
        }

        Item { Layout.fillWidth: true }
        Label {
            id: settingsStatus
            text: ""
            color: Theme.accentSuccess
            font.pixelSize: 11
        }
    }
}
