fn main() {
    // The cxx-qt build script must re-run whenever ANY QML changes: without
    // rerun-if-changed, cargo reused a cached build-script output and the
    // compiled qml module (qmlcachegen + module qrc) shipped STALE QML -
    // the binary kept showing the old views even after source edits.
    for qml in [
        "qml/main.qml",
        "qml/components/AlertHistory.qml",
        "qml/components/ConnectionPrompt.qml",
        "qml/components/DnsSecurityInspector.qml",
        "qml/components/EventFeed.qml",
        "qml/components/LiveTrafficChart.qml",
        "qml/components/ProcessTree.qml",
        "qml/components/Settings.qml",
        "qml/components/SocketTable.qml",
        "qml/components/SystemStatus.qml",
    ] {
        println!("cargo:rerun-if-changed={qml}");
    }
    cxx_qt_build::CxxQtBuilder::new_qml_module(
        cxx_qt_build::QmlModule::new("ring0")
            .version(1, 0)
            .qml_files([
                "qml/main.qml",
                "qml/components/AlertHistory.qml",
                "qml/components/ConnectionPrompt.qml",
                "qml/components/DnsSecurityInspector.qml",
                "qml/components/EventFeed.qml",
                "qml/components/LiveTrafficChart.qml",
                "qml/components/ProcessTree.qml",
                "qml/components/Settings.qml",
                "qml/components/SocketTable.qml",
                "qml/components/SystemStatus.qml",
                            ]),
    )
    .file("src/lib.rs")
    .qt_module("Quick")
    .build();
}
