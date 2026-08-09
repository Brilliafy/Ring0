import QtQuick 2.15
import Qt.labs.settings 1.1

// RingZero design-system theme tokens (see Design system.md). Every view
// reads these properties; never hard-code colors in components.
// mode: "dark" | "light" | "system" (system = follow OS, auto re-evaluates).
QtObject {
    id: theme

    property string mode: "system"

    // Persist the chosen mode. (QtObject has no default child property, so
    // the Settings element must be declared as a property value.)
    property Settings store: Settings {
        category: "theme"
        property string mode: "system"
    }

    // Load persisted mode at startup; write back on changes.
    onModeChanged: {
        if (store.mode !== mode) store.mode = mode
    }
    Component.onCompleted: {
        mode = store.mode
    }

    readonly property bool isDark: mode === "dark"
        || (mode === "system" && Qt.styleHints.colorScheme === Qt.Dark)

    // ── Core surfaces ──
    readonly property color bgBase:      isDark ? "#0d1117" : "#f6f8fa"
    readonly property color bgSurface:   isDark ? "#161b22" : "#ffffff"
    readonly property color bgSurfaceAlt:isDark ? "#21262d" : "#f0f3f6"
    readonly property color bgInput:     isDark ? "#0d1117" : "#ffffff"
    readonly property color bgHover:     isDark ? "#2a3038" : "#eaeef2"
    readonly property color bgOverlay:   isDark ? "#0d1117e6" : "#f6f8fae6"

    // ── Borders & dividers ──
    readonly property color borderDefault: isDark ? "#30363d" : "#d1d9e0"
    readonly property color borderStrong:  isDark ? "#3d444d" : "#b6c2cc"
    readonly property color divider:       isDark ? "#21262d" : "#e1e6eb"

    // ── Text ──
    readonly property color textPrimary:   isDark ? "#e6edf3" : "#1f2328"
    readonly property color textSecondary: isDark ? "#8b949e" : "#59636e"
    readonly property color textMuted:     isDark ? "#6e7681" : "#8c959f"
    readonly property color textOnAccent:  isDark ? "#0d1117" : "#ffffff"

    // ── Semantic accents ──
    readonly property color accentInfo:   isDark ? "#58a6ff" : "#0969da"
    readonly property color accentSuccess:isDark ? "#3fb950" : "#1a7f37"
    readonly property color accentWarning:isDark ? "#d29922" : "#9a6700"
    readonly property color accentDanger: isDark ? "#f85149" : "#d1242f"
    readonly property color accentPurple: isDark ? "#bc8cff" : "#8250df"

    // ── Type scale (px) ──
    readonly property int fontMicro: 9
    readonly property int fontLabel: 10
    readonly property int fontMeta: 11
    readonly property int fontBody: 12
    readonly property int fontEmphasis: 14
    readonly property int fontTitle: 16
    readonly property int fontStat: 20

    // ── Radius ──
    readonly property int radiusInput: 4
    readonly property int radiusCard: 6
    readonly property int radiusIcon: 8
    readonly property int radiusDialog: 12

    // ── Severity → accent ──
    function severityColor(sev) {
        switch (sev) {
        case "CRITICAL": return accentDanger
        case "HIGH": return accentWarning
        case "MED": case "MEDIUM": return accentPurple
        default: return textMuted
        }
    }

    // ── Theming helpers used by views ──
    function rowColor(index, selected) {
        if (selected) return accentInfo + "22" // 13% tint
        return index % 2 === 0 ? bgSurface : bgSurfaceAlt
    }
    function shadow(modal) {
        return modal ? (isDark ? "#00000040" : "#1f23281f") : "transparent"
    }

    function setMode(m) {
        if (m === "dark" || m === "light" || m === "system") mode = m
    }
}
