@echo off
set "LIBCLANG_PATH="
set "MOSQUITTO_PLUGIN_CLANG_EXTRA_ARGS=-IC:\mosquitto_devel"
call "D:\Program Files\Microsoft Visual Studio\2022\VC\Auxiliary\Build\vcvars64.bat"
cargo build --release
