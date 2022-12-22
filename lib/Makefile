libSEP256.dylib: libSEP256-arm64.dylib libSEP256-x86_64.dylib
	lipo -create $^ -output $@

libSEP256-arm64.dylib: SEP256.swift
	xcrun -sdk macosx swiftc $^ -module-name SEP256 -target arm64-apple-macos10.15 -framework CryptoKit -emit-library -o $@

libSEP256-x86_64.dylib: SEP256.swift
	xcrun -sdk macosx swiftc $^ -module-name SEP256 -target x86_64-apple-macos10.15 -framework CryptoKit -emit-library -o $@

clean:
	rm -f libSEP256.dylib libSEP256-arm64.dylib libSEP256-x86_64.dylib
