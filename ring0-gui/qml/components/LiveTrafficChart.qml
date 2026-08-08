import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Shapes 1.15

// Live event-rate chart. The GUI feeds it one data point per status tick
// (events/sec from the daemon status broadcast); it renders a scrolling line
// instead of the previous random-art generator.
Item {
    id: root
    property real currentValue: 0
    property int maxPoints: 60
    property var history: []
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
            var n = root.history.length;
            for (var i = 0; i < width; i += 2) {
                var idx = n - 1 - Math.floor(i / width * maxPoints)
                var v = (idx >= 0) ? root.history[idx] : 0
                // scale: assume up to 2000 events/s fills the chart
                var y = height - Math.min(v / 2000, 1) * (height - 8) - 4
                if (i === 0) ctx.moveTo(i, y)
                else ctx.lineTo(i, y)
            }
            ctx.stroke();
        }
    }

    Label {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.margins: 4
        text: "Events/s: " + root.currentValue.toFixed(1)
        color: "#58a6ff"
        font.pixelSize: 11
    }

    // Push a new events/sec sample; re-render.
    function addValue(v) {
        currentValue = v
        history.push(v)
        if (history.length > maxPoints) {
            history.shift()
        }
        canvas.requestPaint()
    }

    Timer {
        interval: 1000
        running: true
        repeat: true
        onTriggered: canvas.requestPaint()
    }
}
