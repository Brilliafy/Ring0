cmake_minimum_required(VERSION 3.16)
project(ring0-gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick)

# Find the CXX-Qt generated build artifacts from cargo
set(CARGO_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../target")
set(BUILD_DIR "${CARGO_TARGET_DIR}/debug/build")

# Find the latest ring0-gui build output
file(GLOB RING0_GUI_BUILD_DIRS "${BUILD_DIR}/ring0-gui-*/out")
list(SORT RING0_GUI_BUILD_DIRS)
list(REVERSE RING0_GUI_BUILD_DIRS)
list(GET RING0_GUI_BUILD_DIRS 0 CXXQT_OUT_DIR)

message(STATUS "CXX-Qt build output: ${CXXQT_OUT_DIR}")

# Generated CXX-Qt source files
set(CXXQT_GEN_DIR "${CXXQT_OUT_DIR}/cxx-qt-gen")
file(GLOB CXXQT_SOURCES "${CXXQT_GEN_DIR}/src/*.cpp")
file(GLOB CXXQT_COMMON_SOURCES "${CXXQT_OUT_DIR}/cxx-qt-common/*.cpp")

# CXX-Qt headers
set(CXXQT_COMMON_DIR "${CXXQT_OUT_DIR}/cxx-qt-common")
set(CXXQT_LIB_DIR "${CXXQT_OUT_DIR}/cxx-qt-lib")

# Qt resource file for QML
set(QRC_FILE "${CMAKE_CURRENT_SOURCE_DIR}/resources.qrc")
qt_add_resources(ring0_qml QRC_FILE)

# Build the CXX-Qt generated C++ into an object library
add_library(ring0-gui-cpp OBJECT ${CXXQT_SOURCES})
target_include_directories(ring0-gui-cpp PRIVATE
    "${CXXQT_GEN_DIR}"
    "${CXXQT_COMMON_DIR}"
    "${CXXQT_LIB_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CXXQT_OUT_DIR}"
)
target_compile_definitions(ring0-gui-cpp PRIVATE
    CXX_QT_GUI_FEATURE
    CXX_QT_QML_FEATURE
)
target_link_libraries(ring0-gui-cpp PUBLIC
    Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick
)

# Build the Rust library
set(RING0_GUI_LIB "${CARGO_TARGET_DIR}/debug/libring0_gui.a")
add_custom_command(
    OUTPUT ${RING0_GUI_LIB}
    COMMAND cargo build -p ring0-gui
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
    COMMENT "Building ring0-gui Rust library..."
)

# Create the final executable
add_executable(ring0-gui
    "main.cpp"
    ${ring0_qml_QRC_FILE}
    $<TARGET_OBJECTS:ring0-gui-cpp>
)
target_link_libraries(ring0-gui PRIVATE
    ${RING0_GUI_LIB}
    Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick
    pthread dl rt
)
add_dependencies(ring0-gui ${RING0_GUI_LIB})
