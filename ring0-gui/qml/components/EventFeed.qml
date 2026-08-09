import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Live feed of EVERY daemon event (exec, connect, alert, packet drop, dpi,
// self-defense, file access). Color-coded by kind so the operator can tell
// normal activity from security-relevant signals at a glance.
Rectangle {
    id: root
    color: Theme.bgSurface
    radius: 6
    border.color: Theme.borderDefault
    border.width: 1

    property var feedModel: ListModel {}
    property string filterText: ""

    function kindColor(kind) {
        switch (kind) {
        case "alert": return Theme.accentDanger
        case "packet": return Theme.accentWarning
        case "dpi": return Theme.accentWarning
        case "selfDefense": return Theme.accentDanger
        case "fileAccess": return Theme.accentWarning
        case "connect": return Theme.accentInfo
        case "processExec": return Theme.accentSuccess
        case "dns": return Theme.accentPurple
        default: return Theme.textSecondary
        }
    }

    function appendEvent(kind, ts, summary) {
        if (feedModel.count > 800) {
            feedModel.remove(800, feedModel.count - 800)
        }
        // role named 'color' is shadowed by Rectangle.color in delegates -
        // use pillColor to avoid the self-referencing binding.
        feedModel.insert(0, { kind: kind, ts: ts, summary: summary, pillColor: kindColor(kind) })
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
            color: index % 2 === 0 ? Theme.bgSurface : Theme.bgBase
            visible: root.filterText.length === 0 || summary.indexOf(root.filterText) >= 0
            RowLayout {
                anchors.fill: parent
                anchors.margins: 2
                spacing: 6
                Rectangle {
                    width: 46; height: 12; radius: 3
                    color: pillColor
                    Layout.alignment: Qt.AlignVCenter
                    Label {
                        anchors.centerIn: parent
                        text: kind.toUpperCase()
                        color: Theme.bgBase
                        font.pixelSize: 8
                        font.bold: true
                    }
                }
                Label { text: ts; color: Theme.textSecondary; font.pixelSize: 10; Layout.preferredWidth: 90 }
                Label {
                    text: summary
                    color: Theme.textPrimary
                    font.pixelSize: 10
                    Layout.fillWidth: true
                    elide: Text.ElideRight
                }
            }
        }
        footer: Rectangle { width: parent.width; height: 2; color: Theme.borderDefault }
    }
}
