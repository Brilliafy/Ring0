import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Daemon health + maintenance: live CPU/RAM/events, feed/blocklist counts,
// dropped-event counter, and operator actions (scan, sync, reload, shutdown).
Rectangle {
    id: root
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    property int cpuPct: 0
    property int ramMb: 0
    property real eps: 0
    property int droppedEvents: 0
    property int blockedDomains: 0
    property int blockedCidrs: 0
    property int blockedPorts: 0
    property int activeFilters: 0

    function updateFromStatus(evt) {
        if (typeof evt.cpuUsagePercent === "number") cpuPct = Math.round(evt.cpuUsagePercent)
        if (typeof evt.ramUsageBytes === "number") ramMb = Math.round(evt.ramUsageBytes / 1048576)
        if (typeof evt.eventsPerSec === "number") eps = evt.eventsPerSec
        if (typeof evt.droppedEvents === "number") droppedEvents = evt.droppedEvents
        if (typeof evt.blockedDomains === "number") blockedDomains = evt.blockedDomains
        if (typeof evt.blockedCidrs === "number") blockedCidrs = evt.blockedCidrs
        if (typeof evt.blockedPorts === "number") blockedPorts = evt.blockedPorts
        if (evt.activeFilters) activeFilters = evt.activeFilters.length
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 10

        Label { text: "Daemon Health"; color: "#58a6ff"; font.pixelSize: 15; font.bold: true }

        GridLayout {
            columns: 4
            columnSpacing: 12
            rowSpacing: 8
            Layout.fillWidth: true

            Rectangle { color: "#0d1117"; radius: 4; Layout.fillWidth: true; Layout.preferredHeight: 52; border.color: "#30363d"
                ColumnLayout { anchors.centerIn: parent; spacing: 0
                    Label { text: "CPU"; color: "#8b949e"; font.pixelSize: 9 }
                    Label { text: root.cpuPct + "%"; color: root.cpuPct > 60 ? "#f85149" : "#58a6ff"; font.pixelSize: 16; font.bold: true }
                } }
            Rectangle { color: "#0d1117"; radius: 4; Layout.fillWidth: true; Layout.preferredHeight: 52; border.color: "#30363d"
                ColumnLayout { anchors.centerIn: parent; spacing: 0
                    Label { text: "RAM"; color: "#8b949e"; font.pixelSize: 9 }
                    Label { text: root.ramMb + " MB"; color: "#3fb950"; font.pixelSize: 16; font.bold: true }
                } }
            Rectangle { color: "#0d1117"; radius: 4; Layout.fillWidth: true; Layout.preferredHeight: 52; border.color: "#30363d"
                ColumnLayout { anchors.centerIn: parent; spacing: 0
                    Label { text: "Events/s"; color: "#8b949e"; font.pixelSize: 9 }
                    Label { text: root.eps.toFixed(0); color: "#d2a8ff"; font.pixelSize: 16; font.bold: true }
                } }
            Rectangle { color: "#0d1117"; radius: 4; Layout.fillWidth: true; Layout.preferredHeight: 52; border.color: "#30363d"
                ColumnLayout { anchors.centerIn: parent; spacing: 0
                    Label { text: "Dropped events"; color: "#8b949e"; font.pixelSize: 9 }
                    Label { text: root.droppedEvents; color: root.droppedEvents > 0 ? "#d29922" : "#8b949e"; font.pixelSize: 16; font.bold: true }
                } }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12
            Label { text: "Active filters: " + root.activeFilters; color: "#d2a8ff"; font.pixelSize: 11 }
            Label { text: "Domains: " + root.blockedDomains; color: "#d2a8ff"; font.pixelSize: 11 }
            Label { text: "CIDRs: " + root.blockedCidrs; color: "#58a6ff"; font.pixelSize: 11 }
            Label { text: "Ports: " + root.blockedPorts; color: "#f0883e"; font.pixelSize: 11 }
        }

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: "#30363d" }

        Label { text: "Maintenance"; color: "#d2a8ff"; font.pixelSize: 13; font.bold: true }

        GridLayout {
            columns: 3
            columnSpacing: 8
            rowSpacing: 6
            Layout.fillWidth: true

            Button { text: "Run Rootkit Scan"; onClicked: { bridge.runRootkitScan(); systemMsg.text = "Rootkit scan requested" } }
            Button { text: "Sync Intel Feeds"; onClicked: { bridge.syncIntelFeeds(); systemMsg.text = "Feed sync requested" } }
            Button { text: "Reload Rules"; onClicked: { bridge.reloadRules(); systemMsg.text = "Rules reload requested" } }
            Button { text: "Reload Filters"; onClicked: { bridge.reloadFilters(); systemMsg.text = "Filters reload requested" } }
            Button { text: "Run Doctor"; onClicked: { bridge.runDoctor(); systemMsg.text = "Doctor check requested" } }
            Button { text: "Power Status"; onClicked: { bridge.powerStatus(); systemMsg.text = "Power status requested" } }
            Button { text: "Shutdown Daemon"; flat: true; onClicked: { bridge.shutdownDaemon(); systemMsg.text = "Shutdown sent" } }
        }

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: "#30363d" }

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#8b949e"
            font.pixelSize: 10
            text: "Detection modes: LSM and fast-path DPI default to AUDIT (report-only). Set RING0_DPI_ENFORCE=1 / RING0_LSM_ENFORCE=1 at daemon start to drop matching traffic."
        }

        Label { id: systemMsg; text: ""; color: "#3fb950"; font.pixelSize: 11 }
    }
}
