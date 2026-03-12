@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set "LIBCLANG_PATH=D:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin"
set "MOSQUITTO_PLUGIN_CLANG_EXTRA_ARGS=-IC:\mosquitto_devel"
cargo build --release
