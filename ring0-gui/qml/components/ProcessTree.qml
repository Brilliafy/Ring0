import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    color: "#161b22"
    radius: 6
    border.color: "#30363d"
    border.width: 1

    property var processModel: ListModel {}
    property var socketModel: ListModel {}

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 4
        spacing: 4

        Label {
            text: "Process Tree"
            color: "#58a6ff"
            font.pixelSize: 12
            font.bold: true
            leftPadding: 4
        }

        ListView {
            id: processListView
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: processModel
            delegate: Rectangle {
                width: parent.width
                height: 22
                color: index % 2 === 0 ? "#161b22" : "#0d1117"
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Label { text: pid; color: "#f85149"; font.pixelSize: 10; Layout.preferredWidth: 45 }
                    Label { text: ppid; color: "#8b949e"; font.pixelSize: 10; Layout.preferredWidth: 45 }
                    Label { text: binary; color: "#c9d1d9"; font.pixelSize: 10; Layout.fillWidth: true; elide: Text.ElideRight }
                    Label { text: cmdline; color: "#484f58"; font.pixelSize: 9; Layout.preferredWidth: 200; elide: Text.ElideRight }
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#30363d"
        }

        Label {
            text: "Recent Connections"
            color: "#58a6ff"
            font.pixelSize: 12
            font.bold: true
            leftPadding: 4
        }

        ListView {
            id: socketListView
            Layout.fillWidth: true
            Layout.preferredHeight: 80
            clip: true
            model: socketModel
            delegate: Rectangle {
                width: parent.width
                height: 20
                color: index % 2 === 0 ? "#161b22" : "#0d1117"
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 6
                    Label { text: ip; color: "#58a6ff"; font.pixelSize: 10; Layout.preferredWidth: 110 }
                    Label { text: port; color: "#d2a8ff"; font.pixelSize: 10; Layout.preferredWidth: 50 }
                    Label { text: proto; color: "#8b949e"; font.pixelSize: 10; Layout.fillWidth: true }
                }
            }
        }
    }
}
