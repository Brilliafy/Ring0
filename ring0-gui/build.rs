fn main() {
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
