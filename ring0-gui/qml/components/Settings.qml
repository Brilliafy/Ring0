import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

// Settings panel. Every control here is either wired to the daemon through the
// bridge, or clearly informational. (The previous Slack/Discord/Syslog
// "SIEM exporters" fields were cosmetic — the daemon had no such feature, so
// they were removed rather than pretending to configure them.)
Rectangle {
    id: settingsRoot
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 16

        Label {
            text: "Settings & Configuration"
            color: "#58a6ff"
            font.pixelSize: 16
            font.bold: true
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        // ── Enforcement mode (informational — set at daemon start) ──
        Label { text: "Detection Modes"; color: "#d2a8ff"; font.pixelSize: 13; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#8b949e"
            font.pixelSize: 11
            text: "LSM (ptrace/capable) and fast-path DPI default to AUDIT — they report matches and never break the flow. "
                  + "To drop matching traffic / deny capability usage, restart the daemon with RING0_DPI_ENFORCE=1 and/or RING0_LSM_ENFORCE=1."
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        // ── Response: block / kill ──
        Label { text: "Threat Response"; color: "#d2a8ff"; font.pixelSize: 13; font.bold: true }

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
                        settingsStatus.text = "Block sent (requires root/ring0)"
                    }
                }
            }
            Button {
                text: "Unblock"
                flat: true
                onClicked: {
                    if (blockIpField.text.trim().length > 0) {
                        bridge.unblockIp(blockIpField.text.trim())
                        settingsStatus.text = "Unblock sent (requires root/ring0)"
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Label { text: "Reload rules:"; color: "#8b949e"; font.pixelSize: 12 }
            Button {
                text: "Reload"
                onClicked: {
                    bridge.reloadRules()
                    settingsStatus.text = "Reload sent"
                }
            }
            Item { Layout.fillWidth: true }
            Button {
                text: "Shutdown Daemon"
                flat: true
                onClicked: {
                    bridge.shutdownDaemon()
                    settingsStatus.text = "Shutdown sent"
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        // ── Sensitivity (sent to the daemon; daemon-side persistence is TODO) ──
        Label { text: "Sensitivity & Thresholds"; color: "#d2a8ff"; font.pixelSize: 13; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#484f58"
            font.pixelSize: 10
            text: "Note: the daemon currently logs these values; live enforcement wiring is not implemented yet."
        }

        GridLayout {
            columns: 3
            columnSpacing: 12
            rowSpacing: 8
            Layout.fillWidth: true

            Label { text: "CPU Governor Threshold:"; color: "#8b949e"; font.pixelSize: 12 }
            Slider {
                id: cpuSlider
                from: 1; to: 10; value: 3; stepSize: 0.5
                Layout.fillWidth: true
                Layout.preferredHeight: 20
            }
            Label { text: cpuSlider.value.toFixed(1) + "%"; color: "#c9d1d9"; font.pixelSize: 12 }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        // ── Actions ──
        RowLayout {
            Layout.fillWidth: true
            spacing: 12
            Button {
                text: "Save Settings"
                highlighted: true
                onClicked: {
                    var cfg = {
                        cpuThreshold: cpuSlider.value,
                        darkMode: settingsRoot.darkMode
                    }
                    bridge.updateSettings(JSON.stringify(cfg))
                    settingsStatus.text = "Saved (daemon logs; not yet enforced)"
                }
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
}
