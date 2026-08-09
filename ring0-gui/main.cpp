// RingZero GUI entry point.
// The Theme is a C++ QObject (ThemePalette) exposed as the "Theme" context
// property - the earlier QML Theme.qml could fail to instantiate (Settings
// init, QtObject default-property, platform variance), which silently left
// every Theme.* token undefined and spammed 'Unable to assign [undefined]'.
// A plain C++ object cannot fail to construct.
#include <QColor>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QSettings>
#include <QStyleHints>
#include <QtQml>
#include <QObject>
#include "ring0-gui/src/lib.cxxqt.h"

// ── Design-system theme tokens (see Design system.md) ──
class ThemePalette : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString mode READ mode WRITE setMode NOTIFY changed)
    Q_PROPERTY(bool isDark READ isDark NOTIFY changed)
    // surfaces
    Q_PROPERTY(QColor bgBase READ bgBase NOTIFY changed)
    Q_PROPERTY(QColor bgSurface READ bgSurface NOTIFY changed)
    Q_PROPERTY(QColor bgSurfaceAlt READ bgSurfaceAlt NOTIFY changed)
    Q_PROPERTY(QColor bgInput READ bgInput NOTIFY changed)
    Q_PROPERTY(QColor bgHover READ bgHover NOTIFY changed)
    Q_PROPERTY(QColor bgOverlay READ bgOverlay NOTIFY changed)
    // borders
    Q_PROPERTY(QColor borderDefault READ borderDefault NOTIFY changed)
    Q_PROPERTY(QColor borderStrong READ borderStrong NOTIFY changed)
    Q_PROPERTY(QColor divider READ divider NOTIFY changed)
    // text
    Q_PROPERTY(QColor textPrimary READ textPrimary NOTIFY changed)
    Q_PROPERTY(QColor textSecondary READ textSecondary NOTIFY changed)
    Q_PROPERTY(QColor textMuted READ textMuted NOTIFY changed)
    Q_PROPERTY(QColor textOnAccent READ textOnAccent NOTIFY changed)
    // accents
    Q_PROPERTY(QColor accentInfo READ accentInfo NOTIFY changed)
    Q_PROPERTY(QColor accentSuccess READ accentSuccess NOTIFY changed)
    Q_PROPERTY(QColor accentWarning READ accentWarning NOTIFY changed)
    Q_PROPERTY(QColor accentDanger READ accentDanger NOTIFY changed)
    Q_PROPERTY(QColor accentPurple READ accentPurple NOTIFY changed)
    // type scale (px)
    Q_PROPERTY(int fontMicro READ fontMicro CONSTANT)
    Q_PROPERTY(int fontLabel READ fontLabel CONSTANT)
    Q_PROPERTY(int fontMeta READ fontMeta CONSTANT)
    Q_PROPERTY(int fontBody READ fontBody CONSTANT)
    Q_PROPERTY(int fontEmphasis READ fontEmphasis CONSTANT)
    Q_PROPERTY(int fontTitle READ fontTitle CONSTANT)
    Q_PROPERTY(int fontStat READ fontStat CONSTANT)
    // radius
    Q_PROPERTY(int radiusInput READ radiusInput CONSTANT)
    Q_PROPERTY(int radiusCard READ radiusCard CONSTANT)
    Q_PROPERTY(int radiusIcon READ radiusIcon CONSTANT)
    Q_PROPERTY(int radiusDialog READ radiusDialog CONSTANT)

public:
    explicit ThemePalette(QObject *parent = nullptr) : QObject(parent)
    {
        // Persist the mode across restarts (org identity set in main()).
        QSettings s;
        m_mode = s.value("theme/mode", QStringLiteral("system")).toString();
    }

    QString mode() const { return m_mode; }
    void setMode(const QString &m)
    {
        if (m == "dark" || m == "light" || m == "system") {
            if (m_mode != m) {
                m_mode = m;
                QSettings s;
                s.setValue("theme/mode", m);
                emit changed();
            }
        }
    }

    bool isDark() const
    {
        if (m_mode == "dark") return true;
        if (m_mode == "light") return false;
        // system: follow the OS, live (styleHints colorScheme updates).
        return QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark;
    }

    QColor bgBase()      const { return isDark() ? QColor("#0d1117") : QColor("#f6f8fa"); }
    QColor bgSurface()   const { return isDark() ? QColor("#161b22") : QColor("#ffffff"); }
    QColor bgSurfaceAlt()const { return isDark() ? QColor("#21262d") : QColor("#f0f3f6"); }
    QColor bgInput()     const { return isDark() ? QColor("#0d1117") : QColor("#ffffff"); }
    QColor bgHover()     const { return isDark() ? QColor("#2a3038") : QColor("#eaeef2"); }
    QColor bgOverlay()   const { return isDark() ? QColor("#0d1117e6") : QColor("#f6f8fae6"); }
    QColor borderDefault()const{ return isDark() ? QColor("#30363d") : QColor("#d1d9e0"); }
    QColor borderStrong()const { return isDark() ? QColor("#3d444d") : QColor("#b6c2cc"); }
    QColor divider()     const { return isDark() ? QColor("#21262d") : QColor("#e1e6eb"); }
    QColor textPrimary() const { return isDark() ? QColor("#e6edf3") : QColor("#1f2328"); }
    QColor textSecondary()const{ return isDark() ? QColor("#8b949e") : QColor("#59636e"); }
    QColor textMuted()   const { return isDark() ? QColor("#6e7681") : QColor("#8c959f"); }
    QColor textOnAccent()const { return isDark() ? QColor("#0d1117") : QColor("#ffffff"); }
    QColor accentInfo()  const { return isDark() ? QColor("#58a6ff") : QColor("#0969da"); }
    QColor accentSuccess()const{ return isDark() ? QColor("#3fb950") : QColor("#1a7f37"); }
    QColor accentWarning()const{ return isDark() ? QColor("#d29922") : QColor("#9a6700"); }
    QColor accentDanger()const { return isDark() ? QColor("#f85149") : QColor("#d1242f"); }
    QColor accentPurple()const { return isDark() ? QColor("#bc8cff") : QColor("#8250df"); }

    int fontMicro() const { return 9; }
    int fontLabel() const { return 10; }
    int fontMeta() const { return 11; }
    int fontBody() const { return 12; }
    int fontEmphasis() const { return 14; }
    int fontTitle() const { return 16; }
    int fontStat() const { return 20; }

    int radiusInput() const { return 4; }
    int radiusCard() const { return 6; }
    int radiusIcon() const { return 8; }
    int radiusDialog() const { return 12; }

    Q_INVOKABLE QColor severityColor(const QString &sev) const
    {
        if (sev == "CRITICAL") return accentDanger();
        if (sev == "HIGH") return accentWarning();
        if (sev == "MED" || sev == "MEDIUM") return accentPurple();
        return textMuted();
    }
    Q_INVOKABLE QColor rowColor(int index, bool selected) const
    {
        if (selected) return QColor(accentInfo().red(), accentInfo().green(), accentInfo().blue(), 32);
        return index % 2 == 0 ? bgSurface() : bgSurfaceAlt();
    }
    Q_INVOKABLE QColor shadow(bool modal) const
    {
        return modal ? (isDark() ? QColor("#40000000") : QColor("#1f1f2328"))
                     : QColor(Qt::transparent);
    }

signals:
    void changed();

private:
    QString m_mode = QStringLiteral("system");
};

#include "main.moc"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("RingZero"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("ring0.local"));
    QCoreApplication::setApplicationName(QStringLiteral("ring0-gui"));

    QQmlApplicationEngine engine;

    qmlRegisterType<ring0::Ring0Bridge>("ring0", 1, 0, "Ring0Bridge");

    // The Theme is a plain C++ object - it cannot fail to construct, so the
    // Theme.* tokens are guaranteed to resolve.
    ThemePalette *theme = new ThemePalette(&app);
    engine.rootContext()->setContextProperty("Theme", theme);

    ring0::Ring0Bridge *bridge = new ring0::Ring0Bridge(&app);
    engine.rootContext()->setContextProperty("bridge", bridge);

    const char *socketEnv = qgetenv("RING0_SOCKET");
    const QString daemonSocket =
        (socketEnv && *socketEnv) ? QString::fromUtf8(socketEnv) : QStringLiteral("/run/ring0d.sock");
    engine.rootContext()->setContextProperty("daemonSocket", daemonSocket);

    engine.load(QUrl(QStringLiteral("qrc:/qml/main.qml")));

    return app.exec();
}
