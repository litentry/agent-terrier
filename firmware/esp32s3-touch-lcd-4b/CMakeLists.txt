# AgentKeys on-device firmware — Waveshare ESP32-S3-Touch-LCD-4B (issue #348)
# The device is a thin voice client to its assigned cloud agent (a hermes-sandbox
# instance); the LVGL UI mirrors the volcano-probe TUI. Board pins are owned by the
# official BSP component (main/idf_component.yml) — none are hand-coded here.
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32s3-touch-lcd-4b)
