import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import Qt.labs.platform 1.1
import "components"

ApplicationWindow {
    id: appWindow
    visible: true
    width: 1280
    height: 800
    title: "RingZero — Security Command Center"
    color: "#0d1117"

    property bool daemonConnected: false
    property int alertCount: 0
    property string pendingAlertMsg: ""
    property string pendingAlertIp: ""
    property int protectionStatus: 0 // 0=protected, 1=degraded, 2=threat

    property QtObject promptWindow: null

    signal doBlockIp(string ip)
    signal doKillProcess(int pid)

    SystemTrayIcon {
        id: trayIcon
        visible: true
        icon.source: protectionStatus === 0 ? "qrc:/icons/shield_green.png" :
                     protectionStatus === 1 ? "qrc:/icons/shield_yellow.png" :
                     "qrc:/icons/shield_red.png"
        tooltip: "RingZero — " + (protectionStatus === 0 ? "Protected" :
                                   protectionStatus === 1 ? "Degraded" :
                                   "Active Threat")

        menu: Menu {
            MenuItem {
                text: "Open Dashboard"
                onTriggered: { appWindow.show(); appWindow.raise(); }
            }
            MenuItem {
                text: "Pause Protection (5m)"
                onTriggered: { /* send pause command */ }
            }
            MenuItem {
                text: "Reload Rules"
                onTriggered: { /* send reload command */ }
            }
            MenuItem { separator: true }
            MenuItem {
                text: "Quit"
                onTriggered: { Qt.quit(); }
            }
        }

        onActivated: {
            appWindow.show();
            appWindow.raise();
        }
    }

    function setStatusProtected() { protectionStatus = 0 }
    function setStatusDegraded() { protectionStatus = 1 }
    function setStatusThreat() { protectionStatus = 2 }

    header: ToolBar {
        background: Rectangle { color: "#161b22" }
        RowLayout {
            anchors.fill: parent
            spacing: 8
            Label {
                text: "⭕ RingZero"
                font.pixelSize: 18
                font.bold: true
                color: "#58a6ff"
                leftPadding: 12
            }
            Item { Layout.fillWidth: true }
            Label {
                text: daemonConnected ? "● Connected" : "○ Disconnected"
                color: daemonConnected ? "#3fb950" : "#f85149"
                font.pixelSize: 12
                rightPadding: 12
            }
            Label {
                id: cpuLabel
                text: ""
                color: "#8b949e"
                font.pixelSize: 11
                rightPadding: 8
                visible: daemonConnected
            }
            Label {
                id: epsLabel
                text: ""
                color: "#8b949e"
                font.pixelSize: 11
                rightPadding: 8
                visible: daemonConnected
            }
            Rectangle {
                width: 8; height: 8; radius: 4
                color: protectionStatus === 0 ? "#3fb950" : protectionStatus === 1 ? "#d29922" : "#f85149"
                Layout.alignment: Qt.AlignVCenter
            }
            Label {
                text: protectionStatus === 0 ? "Protected" : protectionStatus === 1 ? "Degraded" : "Threat"
                color: protectionStatus === 0 ? "#3fb950" : protectionStatus === 1 ? "#d29922" : "#f85149"
                font.pixelSize: 11
                font.bold: true
                rightPadding: 8
            }
            Label {
                id: batteryLabel
                text: "⚡ AC"
                color: "#3fb950"
                font.pixelSize: 11
                rightPadding: 8
                visible: false
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 4
        anchors.margins: 4

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            Rectangle {
                color: "#161b22"
                radius: 6
                Layout.fillWidth: true
                Layout.preferredHeight: 80
                border.color: "#30363d"
                border.width: 1
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Packets/sec"; color: "#8b949e"; font.pixelSize: 10 }
                    Label { id: ppsLabel; text: "0"; color: "#58a6ff"; font.pixelSize: 20; font.bold: true }
                }
            }
            Rectangle {
                color: "#161b22"
                radius: 6
                Layout.fillWidth: true
                Layout.preferredHeight: 80
                border.color: "#30363d"
                border.width: 1
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Alerts"; color: "#8b949e"; font.pixelSize: 10 }
                    Label { id: alertCountLabel; text: "0"; color: "#f85149"; font.pixelSize: 20; font.bold: true }
                }
            }
            Rectangle {
                color: "#161b22"
                radius: 6
                Layout.fillWidth: true
                Layout.preferredHeight: 80
                border.color: "#30363d"
                border.width: 1
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Active Filters"; color: "#8b949e"; font.pixelSize: 10 }
                    Label { id: filterCountLabel; text: "0"; color: "#d2a8ff"; font.pixelSize: 20; font.bold: true }
                }
            }
            Rectangle {
                color: "#161b22"
                radius: 6
                Layout.fillWidth: true
                Layout.preferredHeight: 80
                border.color: "#30363d"
                border.width: 1
                ColumnLayout {
                    anchors.centerIn: parent
                    Label { text: "Process Execs"; color: "#8b949e"; font.pixelSize: 10 }
                    Label { id: procCountLabel; text: "0"; color: "#3fb950"; font.pixelSize: 20; font.bold: true }
                }
            }
        }

        TabBar {
            id: mainTabBar
            Layout.fillWidth: true
            background: Rectangle { color: "#161b22" }
            TabButton { text: "Network"; background: Rectangle { color: mainTabBar.currentIndex === 0 ? "#21262d" : "#161b22" } }
            TabButton { text: "Processes"; background: Rectangle { color: mainTabBar.currentIndex === 1 ? "#21262d" : "#161b22" } }
            TabButton { text: "DNS & Security"; background: Rectangle { color: mainTabBar.currentIndex === 2 ? "#21262d" : "#161b22" } }
            TabButton { text: "Settings"; background: Rectangle { color: mainTabBar.currentIndex === 3 ? "#21262d" : "#161b22" } }
        }

        StackLayout {
            id: contentStack
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: mainTabBar.currentIndex

            // Tab 0: Network
            ColumnLayout {
                spacing: 4
                Rectangle {
                    color: "#161b22"; radius: 6
                    Layout.fillWidth: true; Layout.preferredHeight: 160
                    border.color: "#30363d"; border.width: 1
                    Label { anchors.centerIn: parent; text: "Live Traffic (MB/s)"; color: "#484f58"; font.pixelSize: 14 }
                }
                Rectangle {
                    color: "#161b22"; radius: 6
                    Layout.fillWidth: true; Layout.fillHeight: true
                    border.color: "#30363d"; border.width: 1; clip: true
                    ColumnLayout { anchors.fill: parent; anchors.margins: 4
                        RowLayout { spacing: 4
                            TextField { id: filterInput; placeholderText: "Filter by PID, IP, or Rule..."; color: "#c9d1d9"; placeholderTextColor: "#484f58"; background: Rectangle { color: "#0d1117"; radius: 4; border.color: "#30363d"; border.width: 1 } Layout.fillWidth: true; Layout.preferredHeight: 28 }
                            Button { text: "Clear"; flat: true; onClicked: filterInput.text = "" }
                        }
                        EventLogTable { id: eventList; Layout.fillWidth: true; Layout.fillHeight: true }
                    }
                }
            }

            // Tab 1: Processes
            ProcessTree { id: processTreeComponent }

            // Tab 2: DNS & Security
            ColumnLayout { spacing: 6
                DnsSecurityInspector { Layout.fillWidth: true; Layout.fillHeight: true }
            }

            // Tab 3: Settings
            Settings { id: settingsComponent }
        }
    }

    Popup {
        id: alertPopup
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        x: Math.round((parent.width - width) / 2)
        y: Math.round((parent.height - height) / 3)
        width: 440
        height: 220
        background: Rectangle { color: "#161b22"; radius: 8; border.color: "#f85149"; border.width: 2 }
        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 12
            Label { text: "🚨 THREAT DETECTED"; color: "#f85149"; font.pixelSize: 16; font.bold: true }
            Label { id: alertMsg; text: ""; color: "#c9d1d9"; font.pixelSize: 12; Layout.fillWidth: true; wrapMode: Text.WordWrap }
            RowLayout {
                Layout.fillWidth: true
                spacing: 8
                Button { text: "Block IP"; highlighted: true; onClicked: { doBlockIp(pendingAlertIp); alertPopup.close() } }
                Button { text: "Kill Process"; onClicked: alertPopup.close() }
                Button { text: "Dismiss"; flat: true; onClicked: alertPopup.close() }
            }
        }
    }

    Timer {
        id: pollTimer
        interval: 100
        running: daemonConnected
        repeat: true
        onTriggered: {
            var events = bridge.pollEvents()
            if (events.length === 0) return
            var lines = events.split("\n")
            for (var i = 0; i < lines.length; i++) {
                if (lines[i].length === 0) continue
                try {
                    var evt = JSON.parse(lines[i])
                    processEvent(evt)
                } catch (e) {}
            }
        }
    }

    Timer {
        id: statusTimer
        interval: 5000
        running: daemonConnected
        repeat: true
        onTriggered: {
            bridge.daemonStatus()
        }
    }

    function processEvent(evt) {
        if (evt.type === "packet") {
            eventList.appendPacket(
                new Date(evt.timestamp / 1000000).toLocaleTimeString(),
                intToIp(evt.src_ip),
                intToIp(evt.dst_ip),
                evt.protocol,
                evt.pid.toString(),
                evt.action
            )
            ppsLabel.text = (parseInt(ppsLabel.text) + 1).toString()
        } else if (evt.type === "alert") {
            alertCount++
            alertCountLabel.text = alertCount.toString()
            pendingAlertMsg = evt.signature + " [Rule " + evt.rule_id + "]"
            pendingAlertIp = evt.src_ip
            alertMsg.text = pendingAlertMsg
            alertPopup.open()
            bridge.sendDesktopNotification(evt.severity === "CRITICAL" ? 3 : 2, "RingZero Alert", pendingAlertMsg)
            if (evt.severity === "CRITICAL") { appWindow.setStatusThreat() }
        } else if (evt.type === "connectionPrompt") {
            showPrompt(evt)
        } else if (evt.type === "processExec") {
            processTreeComponent.processModel.insert(0, {
                pid: evt.pid.toString(),
                ppid: evt.ppid.toString(),
                binary: evt.binary || "",
                cmdline: evt.cmdline || ""
            })
            if (processTreeComponent.processModel.count > 500) processTreeComponent.processModel.remove(500, processTreeComponent.processModel.count - 500)
            procCountLabel.text = (parseInt(procCountLabel.text) + 1).toString()
        } else if (evt.type === "connect") {
            processTreeComponent.socketModel.insert(0, {
                ip: intToIp(evt.dst_ip),
                port: evt.dst_port.toString(),
                proto: evt.protocol || "TCP"
            })
            if (processTreeComponent.socketModel.count > 200) processTreeComponent.socketModel.remove(200, processTreeComponent.socketModel.count - 200)
        } else if (evt.type === "fileAccess") {
            alertCount++
            alertCountLabel.text = alertCount.toString()
            pendingAlertMsg = "File access: " + (evt.file || "") + " by " + (evt.binary || "")
            pendingAlertIp = ""
            alertMsg.text = pendingAlertMsg
            alertPopup.open()
        } else if (evt.type === "status") {
            var filters = evt.activeFilters || []
            filterCountLabel.text = filters.length.toString()
            if (typeof evt.cpuUsagePercent === "number")
                cpuLabel.text = "CPU " + evt.cpuUsagePercent.toFixed(1) + "%"
            if (typeof evt.eventsPerSec === "number")
                epsLabel.text = evt.eventsPerSec >= 100 ? evt.eventsPerSec.toFixed(0) + " eps" : evt.eventsPerSec.toFixed(1) + " eps"
        }
    }

    function intToIp(v) {
        if (typeof v === "string") {
            return v
        }
        return ((v >>> 24) & 0xFF) + "." + ((v >>> 16) & 0xFF) + "." + ((v >>> 8) & 0xFF) + "." + (v & 0xFF)
    }

    function showPrompt(evt) {
        if (promptWindow) {
            promptWindow.close()
        }
        var component = Qt.createComponent("components/ConnectionPrompt.qml")
        if (component.status === Component.Ready) {
            promptWindow = component.createObject(appWindow, {
                promptId: evt.promptId,
                binaryPath: evt.binaryPath || "",
                parentBinary: evt.parentBinary || "",
                pid: evt.pid || 0,
                ppid: evt.ppid || 0,
                dstIp: intToIp(evt.dstIp),
                dstPort: evt.dstPort || 0,
                protocol: evt.protocol === 17 ? "UDP" : "TCP",
                countryCode: evt.countryCode || "XX",
                countryName: evt.countryName || "Unknown",
                rdnsName: evt.rdnsName || "",
                timeoutSecs: evt.timeoutSecs || 15
            })
            promptWindow.decisionMade.connect(function(promptId, action, scope) {
                bridge.submitPromptDecision(promptId, action, scope)
            })
            promptWindow.show()
        } else {
            console.error("Failed to load ConnectionPrompt.qml:", component.errorString())
        }
    }

    onDoBlockIp: { bridge.blockIp(ip) }
    onDoKillProcess: { bridge.killProcess(pid) }

    Component.onCompleted: {
        if (bridge) {
            daemonConnected = bridge.connectDaemon(daemonSocket || "/run/ring0d.sock");
            bridge.initDbusNotifications();
        }
    }
}
