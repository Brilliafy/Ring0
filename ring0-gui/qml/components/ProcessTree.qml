import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Live process tree: built from the daemon's /proc snapshot (bridge.listProcesses)
// with parent-child indentation, plus a kill button per row. The snapshot is
// refreshed by a timer in main.qml; recent EXEC events are appended on top so
// new processes are visible immediately.
Rectangle {
    id: root
    color: Theme.bgSurface
    radius: 6
    border.color: Theme.borderDefault
    border.width: 1

    property var treeModel: ListModel {}
    property var execModel: ListModel {}

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 6
        spacing: 4

        RowLayout {
            Layout.fillWidth: true
            spacing: 6
            Label { text: "Live Processes (" + treeModel.count + ")"; color: Theme.accentInfo; font.pixelSize: 12; font.bold: true }
            Item { Layout.fillWidth: true }
            Label { text: "state  PID / command"; color: Theme.textMuted; font.pixelSize: 9 }
        }

        ListView {
            id: treeList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: root.treeModel
            section.property: "depth"
            delegate: Rectangle {
                width: parent.width
                height: 20
                color: index % 2 === 0 ? Theme.bgSurface : Theme.bgBase
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    anchors.leftMargin: 8 + depth * 16
                    spacing: 6
                    Rectangle {
                        width: 34; height: 12; radius: 3
                        color: state === "R" ? Theme.accentSuccess : state === "S" ? Theme.accentInfo : state === "Z" ? Theme.accentDanger : Theme.textSecondary
                        Layout.preferredWidth: 34
                        Layout.alignment: Qt.AlignVCenter
                        Label { anchors.centerIn: parent; text: state; color: Theme.textOnAccent; font.pixelSize: 8; font.bold: true }
                    }
                    // PID is part of the main label (no separate column):
                    // "12345 /usr/bin/grep grep -Fxq ..." reads as one unit.
                    Label {
                        text: (pid + "  " + binary + (cmdline.length > 0 ? "  " + cmdline : "")).slice(0, 220)
                        color: depth === 0 ? Theme.textPrimary : Theme.textSecondary
                        font.pixelSize: 10
                        Layout.fillWidth: true
                        Layout.minimumWidth: 60
                        elide: Text.ElideRight
                    }
                    Button {
                        text: "Kill"
                        flat: true
                        font.pixelSize: 9
                        implicitHeight: 18
                        visible: parseInt(pid) > 1
                        onClicked: {
                            var p = parseInt(pid)
                            if (p > 1) bridge.killProcess(p)
                        }
                    }
                }
            }
        }

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.borderDefault }

        RowLayout {
            Layout.fillWidth: true
            Label { text: "Recently Executed"; color: Theme.accentInfo; font.pixelSize: 12; font.bold: true }
            Item { Layout.fillWidth: true }
            Button {
                text: "Refresh Tree"
                flat: true
                font.pixelSize: 10
                onClicked: root.refresh()
            }
        }

        ListView {
            id: execList
            Layout.fillWidth: true
            Layout.preferredHeight: 100
            clip: true
            model: root.execModel
            delegate: Rectangle {
                width: parent ? parent.width : 0
                height: 20
                color: index % 2 === 0 ? Theme.bgSurface : Theme.bgBase
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Label { text: ts; color: Theme.textSecondary; font.pixelSize: 10; Layout.preferredWidth: 80 }
                    Label { text: pid + "  " + binary; color: Theme.accentSuccess; font.pixelSize: 10; Layout.fillWidth: true; elide: Text.ElideRight }
                }
            }
        }
    }

    // Rebuild the tree from a ProcessListResponse JSON string.
    function setSnapshot(json) {
        try {
            var data = JSON.parse(json)
            var procs = data.processes || []

            // pid -> index for O(1) parent lookup.
            var byPid = {}
            for (var i = 0; i < procs.length; i++) byPid[procs[i].pid] = procs[i]
            treeModel.clear()
            // Assign depths: walk up parent chains; roots (ppid not found) are depth 0.
            function depthOf(p) {
                var d = 0
                var seen = 0
                var cur = p
                while (cur.ppid && byPid[cur.ppid] && byPid[cur.ppid] !== cur && seen < 20) {
                    d++
                    cur = byPid[cur.ppid]
                    seen++
                }
                return d
            }
            for (var j = 0; j < procs.length; j++) {
                var p = procs[j]
                treeModel.append({
                    pid: p.pid, ppid: p.ppid, uid: p.uid,
                    binary: p.binary || "?", cmdline: p.cmdline || "",
                    state: p.state || "?",
                    depth: Math.min(depthOf(p), 6)
                })
            }
        } catch (e) {}
    }

    function refresh() {
        if (bridge && bridge.isConnected()) {
            bridge.listProcesses() // fire-and-forget
        }
    }

    // Collect a pending snapshot response (called from the poll timer).
    function collect() {
        var json = bridge.takeProcesses()
        if (json.length > 0) setSnapshot(json)
    }
}
