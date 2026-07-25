import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    property var tactics: [
        { name: "Execution", color: "#f85149", count: 0, techniques: ["T1059.004", "T1059", "T1106"] },
        { name: "Persistence", color: "#d2a8ff", count: 0, techniques: ["T1543", "T1053"] },
        { name: "Credential Access", color: "#f0883e", count: 0, techniques: ["T1003", "T1041", "T1555"] },
        { name: "Lateral Movement", color: "#58a6ff", count: 0, techniques: ["T1091", "T1021"] },
        { name: "Exfiltration", color: "#7ee787", count: 0, techniques: ["T1041", "T1567"] },
        { name: "Defense Evasion", color: "#ff7b72", count: 0, techniques: ["T1070", "T1562"] },
    ]

    ColumnLayout {
        anchors.fill: parent
        spacing: 4

        Label {
            text: "MITRE ATT&CK Matrix"
            color: "#58a6ff"
            font.pixelSize: 14
            font.bold: true
            leftPadding: 8
        }

        GridView {
            id: matrixGrid
            Layout.fillWidth: true
            Layout.fillHeight: true
            cellWidth: (parent.width - 16) / 3
            cellHeight: 160
            model: tactics
            delegate: Rectangle {
                width: matrixGrid.cellWidth - 8
                height: matrixGrid.cellHeight - 8
                radius: 6
                color: "#161b22"
                border.color: modelData.color
                border.width: 2
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 4
                    Rectangle {
                        color: modelData.color
                        radius: 4
                        Layout.fillWidth: true
                        Layout.preferredHeight: 24
                        Label {
                            text: modelData.name
                            color: "#ffffff"
                            font.pixelSize: 12
                            font.bold: true
                            anchors.centerIn: parent
                        }
                    }
                    Item { Layout.fillHeight: true }
                    Label {
                        text: modelData.count + " alerts"
                        color: "#f0f6fc"
                        font.pixelSize: 24
                        font.bold: true
                    }
                    RowLayout {
                        spacing: 2
                        Repeater {
                            model: modelData.techniques
                            Rectangle {
                                color: "#30363d"
                                radius: 3
                                height: 20
                                Layout.preferredWidth: label.implicitWidth + 8
                                Label {
                                    id: label
                                    text: modelData
                                    color: "#8b949e"
                                    font.pixelSize: 9
                                    anchors.centerIn: parent
                                }
                            }
                        }
                    }
                    Item { Layout.fillHeight: true }
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        techniqueDialog.title = modelData.name + " — " + modelData.count + " alerts"
                        techniqueList.model = modelData.techniques
                        techniqueDialog.open()
                    }
                }
            }
        }
    }

    Dialog {
        id: techniqueDialog
        modal: true
        x: Math.round((parent.width - width) / 2)
        y: Math.round((parent.height - height) / 2)
        width: 400
        height: 300
        background: Rectangle { color: "#161b22"; border.color: "#30363d"; border.width: 1 }
        header: Label { text: "Tactic Detail"; color: "#58a6ff"; font.pixelSize: 14; padding: 8 }
        ListView {
            id: techniqueList
            anchors.fill: parent
            anchors.margins: 8
            delegate: Rectangle {
                height: 28
                color: index % 2 === 0 ? "#161b22" : "#0d1117"
                Label {
                    text: modelData
                    color: "#c9d1d9"
                    font.pixelSize: 12
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.left: parent.left
                    anchors.leftMargin: 8
                }
            }
        }
    }
}
