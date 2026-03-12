@echo off
set "PATH=C:\Users\CarlenKaiser\.cargo\bin;%PATH%"
set "LIBCLANG_PATH=D:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin"
set "MOSQUITTO_PLUGIN_CLANG_EXTRA_ARGS=-IC:\mosquitto_devel"
call "D:\Program Files\Microsoft Visual Studio\2022\VC\Auxiliary\Build\vcvars64.bat"
cargo build --release
