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

# Locate the newest cxx-qt build output that uses the cxx-qt >= 0.9 layout (cxxqtgen/)
file(GLOB RING0_GUI_BUILD_DIRS "${BUILD_DIR}/ring0-gui-*/out")
set(CXXQT_OUT_DIR "")
set(CXXQT_NEWEST_TIME 0)
foreach(dir ${RING0_GUI_BUILD_DIRS})
    if(EXISTS "${dir}/cxxqtgen/src")
        file(TIMESTAMP "${dir}" dir_time "%s")
        if(dir_time GREATER CXXQT_NEWEST_TIME)
            set(CXXQT_NEWEST_TIME ${dir_time})
            set(CXXQT_OUT_DIR "${dir}")
        endif()
    endif()
endforeach()
if(NOT CXXQT_OUT_DIR)
    message(FATAL_ERROR "cxx-qt build output not found. Run: cargo build -p ring0-gui")
endif()
message(STATUS "CXX-Qt build output: ${CXXQT_OUT_DIR}")

set(CXXQT_GEN_DIR "${CXXQT_OUT_DIR}/cxxqtgen")
set(CXXQT_INCLUDE_DIR "${CXXQT_OUT_DIR}/cxxqtbuild/include")

# Generated CXX-Qt source files
file(GLOB CXXQT_SOURCES "${CXXQT_GEN_DIR}/src/*.cpp")

# Qt resource file for QML
set(QRC_FILE "${CMAKE_CURRENT_SOURCE_DIR}/resources.qrc")
qt_add_resources(ring0_qml "${QRC_FILE}")

# Build the CXX-Qt generated C++ into an object library
add_library(ring0-gui-cpp OBJECT ${CXXQT_SOURCES})
target_include_directories(ring0-gui-cpp PRIVATE
    "${CXXQT_INCLUDE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_compile_definitions(ring0-gui-cpp PRIVATE
    CXX_QT_GUI_FEATURE
    CXX_QT_QML_FEATURE
)
target_link_libraries(ring0-gui-cpp PUBLIC
    Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick
)

# Build the Rust library (staticlib)
set(RING0_GUI_LIB "${CARGO_TARGET_DIR}/debug/libring0_gui.a")
add_custom_command(
    OUTPUT ${RING0_GUI_LIB}
    COMMAND cargo build -p ring0-gui
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
    COMMENT "Building ring0-gui Rust library..."
)
add_custom_target(ring0-gui-rust-lib ALL DEPENDS ${RING0_GUI_LIB})

# Create the final executable
add_executable(ring0-gui
    "main.cpp"
    ${ring0_qml}
    $<TARGET_OBJECTS:ring0-gui-cpp>
)
target_include_directories(ring0-gui PRIVATE
    "${CXXQT_INCLUDE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(ring0-gui PRIVATE
    ${RING0_GUI_LIB}
    Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick
    pthread dl rt
)
add_dependencies(ring0-gui ring0-gui-rust-lib)
