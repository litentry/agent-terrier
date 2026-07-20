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
# LVGL's SDL driver includes <SDL2/SDL.h>, but find_package(SDL2) reports the
# include dir as `<prefix>/include/SDL2` (Homebrew/most distros) — the PARENT is
# what satisfies that spelling. LVGL is a FetchContent target we don't control,
# so the parent goes on the global include path BEFORE LVGL is configured.
# (Desktop only; Emscripten's SDL2 port needs none of this.)
if(NOT EMSCRIPTEN)
  find_package(SDL2 REQUIRED)
  foreach(d ${SDL2_INCLUDE_DIRS})
    include_directories(${d})
    get_filename_component(_parent ${d} DIRECTORY)
    include_directories(${_parent})
  endforeach()
endif()

include(FetchContent)
FetchContent_Declare(lvgl
  GIT_REPOSITORY https://github.com/lvgl/lvgl.git
  GIT_TAG v9.5.0   # MUST match the firmware's LVGL (esp_lvgl_port pulls 9.5.0) for true fidelity
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(lvgl)

# cJSON — ESP-IDF bundles it as a component, so net/*.c includes "cJSON.h"
# unqualified. We fetch the same upstream but do NOT use its CMake project
# (cJSON 1.7.x declares cmake_minimum_required < 3.5, which current CMake
# rejects outright). It is two files; compiling the source directly is both
# simpler and avoids pulling in its tests/demos.
FetchContent_Declare(cjson
  GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
  GIT_TAG v1.7.18
  GIT_SHALLOW TRUE
  SOURCE_SUBDIR do-not-configure   # download only — never add_subdirectory()
)
FetchContent_MakeAvailable(cjson)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/..)

# #517 — REAL device mode. Desktop builds compile the firmware's OWN net/ layer
# (real K10 in a file, real §10.2 pairing, real /v1/chat SSE) instead of
# mock_net.c's fixtures, so the desktop app is a mock DEVICE, not a mock
# PROTOCOL — nothing about the broker or daemon is faked.
#
# The browser (Emscripten) build stays on mock_net: no sockets, no pthreads, no
# libcurl in that sandbox, and its job is the UI mirror + the firmware-sim CI
# gate. So this is desktop-only, and the existing WASM gate is untouched.
option(AGENTKEYS_REAL_NET "Compile the real firmware net/ layer (desktop only)" ON)
if(EMSCRIPTEN)
  set(AGENTKEYS_REAL_NET OFF)
endif()

if(AGENTKEYS_REAL_NET)
  set(NET_SOURCES
    ${FW}/main/net/agent_client.c
    ${FW}/main/net/pairing.c
    ${FW}/main/net/device_identity.c
    ${FW}/main/net/channel_client.c
    desktop_wifi.c                    # wifi.c's stand-in: a laptop is always online
    shims/nvs.c
    shims/esp_http_client.c
    sim_config.c
    ${cjson_SOURCE_DIR}/cJSON.c
  )
else()
  set(NET_SOURCES mock_net.c)
endif()

add_executable(mirror
  sim_main.c
  ${NET_SOURCES}
  desktop_audio.c                    # #524 audio_io over SDL2 (WASM-guarded); screen_home links it in BOTH modes
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

if(AGENTKEYS_REAL_NET)
  target_compile_definitions(mirror PRIVATE AGENTKEYS_REAL_NET=1)
  # Force-include sim_config.h so its BROKER_URL/AGENT_* definitions land BEFORE
  # app_config.h's `#ifndef` fallbacks — the firmware sources stay untouched.
  target_compile_options(mirror PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/sim_config.h)
  find_package(CURL REQUIRED)          # the esp_http_client shim's transport
  find_package(Threads REQUIRED)       # the freertos task/queue/semaphore shims
  target_link_libraries(mirror PRIVATE CURL::libcurl Threads::Threads)
  target_include_directories(mirror PRIVATE ${cjson_SOURCE_DIR})

  # The K10 crypto is the firmware's OWN — agentkeys-device-core, the same Rust
  # staticlib the ESP32 links via FFI. Built for the host here, so the desktop
  # device derives its key with byte-identical code, never a reimplementation.
  set(DEVICE_CORE ${FW}/../../crates/agentkeys-device-core)
  set(DEVICE_CORE_LIB ${CMAKE_CURRENT_BINARY_DIR}/device-core/release/libagentkeys_device_core.a)
  # `freestanding` (= ffi + the no_std runtime), the SAME feature the firmware
  # uses. The crate is no_std unconditionally, so ANY standalone staticlib needs
  # its panic handler + C-backed allocator — `ffi` alone fails to link with "no
  # global memory allocator found". The C allocator it calls is plain libc here.
  # crate-type staticlib is opt-in per the crate's Cargo.toml, hence
  # `cargo rustc --crate-type` rather than a plain `cargo build`.
  add_custom_command(
    OUTPUT ${DEVICE_CORE_LIB}
    COMMAND cargo rustc --release --features freestanding --crate-type staticlib
            --manifest-path ${DEVICE_CORE}/Cargo.toml
            --target-dir ${CMAKE_CURRENT_BINARY_DIR}/device-core
            -- -C panic=abort   # no_std has no unwinder; the ESP-IDF profile sets this on-device
    COMMENT "cargo rustc agentkeys-device-core (host staticlib for the K10 FFI)"
    VERBATIM
  )
  add_custom_target(device_core_build DEPENDS ${DEVICE_CORE_LIB})
  add_dependencies(mirror device_core_build)
  # The cbindgen-generated header is COMMITTED under the ESP-IDF component (the
  # firmware's own include path) — the desktop build consumes the same file, so
  # a header regen can't drift between device and mirror.
  target_include_directories(mirror PRIVATE
    ${FW}/components/agentkeys_device/include)
  target_link_libraries(mirror PRIVATE ${DEVICE_CORE_LIB})
  if(APPLE)
    target_link_libraries(mirror PRIVATE "-framework Security" "-framework CoreFoundation")
  endif()
endif()
