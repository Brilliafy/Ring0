fn main() {
    cxx_qt_build::CxxQtBuilder::new_qml_module(
        cxx_qt_build::QmlModule::new("ring0")
            .version(1, 0)
            .qml_files([
                "qml/main.qml",
                "qml/components/ConnectionPrompt.qml",
                "qml/components/DnsSecurityInspector.qml",
                "qml/components/EventLogTable.qml",
                "qml/components/LiveTrafficChart.qml",
                "qml/components/MitreMatrix.qml",
                "qml/components/ProcessTree.qml",
                "qml/components/Settings.qml",
            ]),
    )
    .file("src/lib.rs")
    .qt_module("Quick")
    .build();
}
