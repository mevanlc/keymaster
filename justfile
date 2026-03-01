build:
    mkdir -p dist/bin
    swiftc -O -o dist/bin/keymaster keymaster.swift

clean:
    rm -rf dist
