@echo off
del *.sdf
del *.VC.db
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q HyperPlatform\x64
rmdir /s /q HyperPlatform\Debug
rmdir /s /q HyperPlatform\Release
rmdir /s /q doxygen
pause
