#!/bin/bash

build(){
    swiftc -sdk $(xcrun --show-sdk-path --sdk macosx) -target arm64-apple-macos11 -framework CryptoKit -framework LocalAuthentication -framework Security -framework Foundation device_auth.swift -o "TpmAuth_arm64"
    swiftc -sdk $(xcrun --show-sdk-path --sdk macosx) -target x86_64-apple-macos11 -framework CryptoKit -framework LocalAuthentication -framework Security -framework Foundation device_auth.swift -o "TpmAuth_x86_64"
    lipo -create -output "TpmAuth" "TpmAuth_arm64" "TpmAuth_x86_64"
    rm -rf TpmAuth_arm64 TpmAuth_x86_64
}
build