import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Rectangle {
    id: settingsRoot
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    property bool darkMode: true

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

        // Appearance
        Label { text: "Appearance"; color: "#d2a8ff"; font.pixelSize: 13; font.bold: true }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12
            Label { text: "Theme:"; color: "#8b949e"; font.pixelSize: 12 }
            ButtonGroup { id: themeGroup }
            RadioButton {
                text: "Dark"; checked: true
                ButtonGroup.group: themeGroup
                onCheckedChanged: if (checked) { settingsRoot.darkMode = true }
            }
            RadioButton {
                text: "Light"
                ButtonGroup.group: themeGroup
                onCheckedChanged: if (checked) { settingsRoot.darkMode = false }
            }
            Item { Layout.fillWidth: true }
            Switch {
                text: "System Tray Notifications"
                checked: true
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        // SIEM Exporters
        Label { text: "SIEM & Telemetry Exporters"; color: "#d2a8ff"; font.pixelSize: 13; font.bold: true }

        GridLayout {
            columns: 2
            columnSpacing: 12
            rowSpacing: 8
            Layout.fillWidth: true

            Label { text: "Syslog Endpoint:"; color: "#8b949e"; font.pixelSize: 12 }
            TextField {
                id: syslogEndpoint
                placeholderText: "logs.example.com"
                color: "#c9d1d9"
                placeholderTextColor: "#484f58"
                background: Rectangle { color: "#0d1117"; radius: 4; border.color: "#30363d"; border.width: 1 }
                Layout.fillWidth: true
                Layout.preferredHeight: 28
            }

            Label { text: "Syslog Port:"; color: "#8b949e"; font.pixelSize: 12 }
            SpinBox {
                id: syslogPort
                from: 1; to: 65535; value: 514
                editable: true
                Layout.preferredWidth: 100
            }

            Label { text: "Slack Webhook:"; color: "#8b949e"; font.pixelSize: 12 }
            TextField {
                id: slackWebhook
                placeholderText: "https://hooks.slack.com/services/..."
                color: "#c9d1d9"
                placeholderTextColor: "#484f58"
                background: Rectangle { color: "#0d1117"; radius: 4; border.color: "#30363d"; border.width: 1 }
                Layout.fillWidth: true
                Layout.preferredHeight: 28
            }

            Label { text: "Discord Webhook:"; color: "#8b949e"; font.pixelSize: 12 }
            TextField {
                id: discordWebhook
                placeholderText: "https://discord.com/api/webhooks/..."
                color: "#c9d1d9"
                placeholderTextColor: "#484f58"
                background: Rectangle { color: "#0d1117"; radius: 4; border.color: "#30363d"; border.width: 1 }
                Layout.fillWidth: true
                Layout.preferredHeight: 28
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        // Sensitivity & Thresholds
        Label { text: "Sensitivity & Thresholds"; color: "#d2a8ff"; font.pixelSize: 13; font.bold: true }

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

            Label { text: "DGA Entropy Sensitivity:"; color: "#8b949e"; font.pixelSize: 12 }
            Slider {
                id: entropySlider
                from: 0.0; to: 1.0; value: 0.5; stepSize: 0.05
                Layout.fillWidth: true
                Layout.preferredHeight: 20
            }
            Label { text: entropySlider.value.toFixed(2); color: "#c9d1d9"; font.pixelSize: 12 }

            Label { text: "Syslog TLS:"; color: "#8b949e"; font.pixelSize: 12 }
            CheckBox {
                id: syslogTls
                text: "Enable TLS"
                checked: false
            }
            Item { }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        // Actions
        RowLayout {
            Layout.fillWidth: true
            spacing: 12
            Button {
                text: "Save Settings"
                highlighted: true
                onClicked: {
                    var cfg = {
                        syslogEndpoint: syslogEndpoint.text,
                        syslogPort: syslogPort.value,
                        syslogTls: syslogTls.checked,
                        slackWebhook: slackWebhook.text,
                        discordWebhook: discordWebhook.text,
                        cpuThreshold: cpuSlider.value,
                        dgaSensitivity: entropySlider.value,
                        darkMode: settingsRoot.darkMode
                    }
                    bridge.updateSettings(JSON.stringify(cfg))
                    settingsStatus.text = "Saved"
                }
            }
            Button {
                text: "Export Config"
                flat: true
                onClicked: { /* export to file */ }
            }
            Item { Layout.fillWidth: true }
            Label {
                id: settingsStatus
                text: ""
                color: "#3fb950"
                font.pixelSize: 11
            }
            Button {
                text: "Test Webhook"
                flat: true
                onClicked: {
                    settingsStatus.text = "Test sent (check your channel)"
                }
            }
        }
    }
}
