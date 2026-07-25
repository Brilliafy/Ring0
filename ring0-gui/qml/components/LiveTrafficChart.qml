import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Shapes 1.15

Item {
    property real currentValue: 0
    width: parent.width
    height: 200

    Canvas {
        id: canvas
        anchors.fill: parent
        onPaint: {
            var ctx = getContext("2d");
            ctx.reset();
            ctx.strokeStyle = "#58a6ff";
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.moveTo(0, height);
            for (var i = 0; i < width; i += 2) {
                ctx.lineTo(i, height - (Math.random() * height * 0.5 + height * 0.25));
            }
            ctx.stroke();
        }
    }

    Timer {
        interval: 1000
        running: true
        repeat: true
        onTriggered: canvas.requestPaint()
    }
}
