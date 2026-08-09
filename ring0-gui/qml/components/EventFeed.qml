import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Live feed of EVERY daemon event (exec, connect, alert, packet drop, dpi,
// self-defense, file access). Color-coded by kind so the operator can tell
// normal activity from security-relevant signals at a glance.
Rectangle {
    id: root
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    property var feedModel: ListModel {}
    property string filterText: ""

    function kindColor(kind) {
        switch (kind) {
        case "alert": return "#f85149"
        case "packet": return "#d29922"
        case "dpi": return "#f0883e"
        case "selfDefense": return "#f85149"
        case "fileAccess": return "#f0883e"
        case "connect": return "#58a6ff"
        case "processExec": return "#3fb950"
        case "dns": return "#d2a8ff"
        default: return "#8b949e"
        }
    }

    function appendEvent(kind, ts, summary) {
        if (feedModel.count > 800) {
            feedModel.remove(800, feedModel.count - 800)
        }
        feedModel.insert(0, { kind: kind, ts: ts, summary: summary, color: kindColor(kind) })
    }

    ListView {
        id: feedList
        anchors.fill: parent
        anchors.margins: 4
        clip: true
        model: feedModel
        delegate: Rectangle {
            // parent is null while a row is being destroyed (model clear /
            // cap) - width would throw "Cannot read property 'width' of null".
            width: parent ? parent.width : 0
            height: 22
            color: index % 2 === 0 ? "#161b22" : "#0d1117"
            visible: root.filterText.length === 0 || summary.indexOf(root.filterText) >= 0
            RowLayout {
                anchors.fill: parent
                anchors.margins: 2
                spacing: 6
                Rectangle {
                    width: 46; height: 12; radius: 3
                    color: color
                    Layout.alignment: Qt.AlignVCenter
                    Label {
                        anchors.centerIn: parent
                        text: kind.toUpperCase()
                        color: "#0d1117"
                        font.pixelSize: 8
                        font.bold: true
                    }
                }
                Label { text: ts; color: "#8b949e"; font.pixelSize: 10; Layout.preferredWidth: 90 }
                Label {
                    text: summary
                    color: "#c9d1d9"
                    font.pixelSize: 10
                    Layout.fillWidth: true
                    elide: Text.ElideRight
                }
            }
        }
        footer: Rectangle { width: parent.width; height: 2; color: "#30363d" }
    }
}
