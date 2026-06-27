# Browser/desktop simulator for the AgentKeys device UI — compiles the REAL firmware
# screens (../main/ui/*.c) + ../main/app_state.c against LVGL's SDL backend so the
# mirror can't drift from the device. Built for the browser via Emscripten (emcmake),
# or natively with SDL2 for a desktop window.
#
#   browser : emcmake cmake -B build-web && cmake --build build-web   (-> build-web/index.html)
#   desktop : cmake -B build-pc && cmake --build build-pc             (needs SDL2)
#
# See build.sh / watch.sh (the watcher) and README.md.
cmake_minimum_required(VERSION 3.16)
project(agentkeys_ui_mirror C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Emscripten brings its own SDL2 port; a desktop build finds a system SDL2. Set the
# port BEFORE LVGL is configured so LVGL's SDL driver compiles against it too.
if(EMSCRIPTEN)
  add_compile_options(-sUSE_SDL=2)
  add_link_options(-sUSE_SDL=2 -sWASM=1 -sALLOW_MEMORY_GROWTH=1
                   --shell-file ${CMAKE_CURRENT_SOURCE_DIR}/shell.html)
endif()

# LVGL is configured by lv_conf.h (next to this CMakeLists): LVGL's own CMake finds it
# at ${CMAKE_SOURCE_DIR}/lv_conf.h and sets LV_CONF_INCLUDE_SIMPLE — no -D needed. It's
# derived from LVGL's lv_conf_template.h with LV_USE_SDL / LV_USE_QRCODE / the Montserrat
# fonts enabled (LV_COLOR_DEPTH stays 16 to match the panel's RGB565). Keep it in sync
# with the firmware's LVGL version when bumping the GIT_TAG below.
include(FetchContent)
FetchContent_Declare(lvgl
  GIT_REPOSITORY https://github.com/lvgl/lvgl.git
  GIT_TAG v9.5.0   # MUST match the firmware's LVGL (esp_lvgl_port pulls 9.5.0) for true fidelity
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(lvgl)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/..)
add_executable(mirror
  sim_main.c
  mock_net.c
  ${FW}/main/app_state.c
  ${FW}/main/ui/ui.c
  ${FW}/main/ui/screen_home.c
  ${FW}/main/ui/screen_pairing.c
  ${FW}/main/ui/screen_settings.c
  ${FW}/main/ui/screen_connection.c
  ${FW}/main/ui/screen_voices.c
)
target_include_directories(mirror PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/shims    # esp_log.h, bsp/esp-bsp.h, freertos/* shims
  ${FW}/main
  ${FW}/main/ui
  ${FW}/main/net                       # the real net/*.h (mock_net.c provides the impls)
)
target_link_libraries(mirror PRIVATE lvgl)

if(EMSCRIPTEN)
  set_target_properties(mirror PROPERTIES OUTPUT_NAME index SUFFIX ".html")
else()
  find_package(SDL2 REQUIRED)
  target_link_libraries(mirror PRIVATE SDL2::SDL2)
endif()
