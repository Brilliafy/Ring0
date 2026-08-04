fn main() {
    cxx_qt_build::CxxQtBuilder::new()
        .qml_module(cxx_qt_build::QmlModule {
            uri: "ring0",
            version_major: 1,
            version_minor: 0,
            rust_files: &["src/lib.rs"],
            qml_files: &[
                "qml/main.qml",
                "qml/components/ConnectionPrompt.qml",
                "qml/components/EventLogTable.qml",
                "qml/components/LiveTrafficChart.qml",
                "qml/components/MitreMatrix.qml",
                "qml/components/ProcessTree.qml",
                "qml/components/Settings.qml",
            ],
            ..Default::default()
        })
        .qt_module("Qml")
        .qt_module("Quick")
        .build();
}
