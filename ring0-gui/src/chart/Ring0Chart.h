#pragma once

#include <QQuickPaintedItem>
#include <QPainter>
#include <QPen>
#include <QBrush>
#include <QColor>
#include <QMutex>
#include <QVector>
#include <QPointF>
#include <cmath>

namespace ring0_chart {

class Ring0Chart : public QQuickPaintedItem {
    Q_OBJECT
    Q_PROPERTY(QColor lineColor READ lineColor WRITE setLineColor NOTIFY lineColorChanged)
    Q_PROPERTY(qreal maxValue READ maxValue WRITE setMaxValue NOTIFY maxValueChanged)

public:
    explicit Ring0Chart(QQuickItem *parent = nullptr)
        : QQuickPaintedItem(parent), m_maxValue(100.0), m_lineColor(88, 166, 255) {
        setAntialiasing(true);
    }

    QColor lineColor() const { return m_lineColor; }
    void setLineColor(const QColor &c) {
        if (m_lineColor != c) { m_lineColor = c; emit lineColorChanged(); update(); }
    }

    qreal maxValue() const { return m_maxValue; }
    void setMaxValue(qreal v) {
        if (m_maxValue != v) { m_maxValue = v; emit maxValueChanged(); update(); }
    }

    Q_INVOKABLE void pushValue(qreal v) {
        QMutexLocker lock(&m_mutex);
        m_points.append(QPointF(m_points.size(), v));
        if (m_points.size() > 300) m_points.remove(0, m_points.size() - 300);
        update();
    }

    void paint(QPainter *painter) override {
        painter->setRenderHint(QPainter::Antialiasing);
        painter->fillRect(boundingRect(), QColor("#0d1117"));

        QMutexLocker lock(&m_mutex);
        if (m_points.size() < 2) return;

        qreal w = boundingRect().width();
        qreal h = boundingRect().height();

        QPen gridPen(QColor("#30363d"), 1);
        painter->setPen(gridPen);
        for (int i = 0; i < 4; ++i) {
            qreal y = h * i / 4.0;
            painter->drawLine(QPointF(0, y), QPointF(w, y));
        }

        QPen linePen(m_lineColor, 2);
        painter->setPen(linePen);

        qreal stepX = w / qMax(1.0, (qreal)(m_points.size() - 1));
        QPainterPath path;
        path.moveTo(0, h - (m_points[0].y() / m_maxValue) * h);
        for (int i = 1; i < m_points.size(); ++i) {
            qreal x = i * stepX;
            qreal y = h - qMin(1.0, m_points[i].y() / m_maxValue) * h;
            path.lineTo(x, y);
        }
        painter->drawPath(path);

        QPen fillPen(m_lineColor, 0);
        QLinearGradient grad(0, 0, 0, h);
        grad.setColorAt(0.0, QColor(m_lineColor.red(), m_lineColor.green(), m_lineColor.blue(), 80));
        grad.setColorAt(1.0, QColor(m_lineColor.red(), m_lineColor.green(), m_lineColor.blue(), 10));
        painter->setBrush(grad);
        painter->setPen(fillPen);
        path.lineTo(w, h);
        path.lineTo(0, h);
        path.closeSubpath();
        painter->drawPath(path);
    }

signals:
    void lineColorChanged();
    void maxValueChanged();

private:
    QMutex m_mutex;
    QVector<QPointF> m_points;
    qreal m_maxValue;
    QColor m_lineColor;
};

} // namespace ring0_chart
