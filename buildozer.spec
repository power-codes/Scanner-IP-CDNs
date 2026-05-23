[app]
title = PowerCodes Scanner
package.name = powercodesscanner
package.domain = org.powercodes
source.dir = .
source.include_exts = py
version = 3.0

requirements = python3==3.10.12,kivy==2.3.0,Cython==0.29.33

android.permissions = INTERNET
android.api = 33
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = True
orientation = portrait

[buildozer]
log_level = 2
warn_on_root = 0
