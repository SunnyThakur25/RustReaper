#!/bin/bash
set -e

# Configuration
PROJECT_NAME="rustreaper"
OUTPUT_DIR="target/release"
PACKAGE_DIR="dist"
WEB_DIR="web"
RULES_DIR="rules"
VERSION=$(grep '^version="' Cargo.toml | cut -d'"' -f2)
ARCHIVE_NAME="${PROJECT_NAME}-${VERSION}-$(uname -s | tr '[:upper:]' '[:lower:]').tar.gz"

# Function to check for dependencies
check_deps() {
    echo "Checking dependencies..."
    if ! command -v rustc >/dev/null 2>&1; then
        echo "Error: Rust is not installed. Install it from https://www.rust-lang.org/tools/install"
        exit 1
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        echo "Error: Cargo is not installed. Install Rust from https://www.rust-lang.org/tools/install"
        exit 1
    fi

    case "$(uname -s)" in
        Linux)
            if ! dpkg-query -W -f='${Status}' libsqlite3-dev >/dev/null 2>&1; then
                echo "Installing libsqlite3-dev..."
                sudo apt-get update && sudo apt-get install -y libsqlite3-dev
            fi
            ;;
        Darwin)
            if ! command -v sqlite3 >/dev/null 2>&1; then
                echo "Installing SQLite3..."
                brew install sqlite3
            fi
            ;;
    esac
}

# Function to clean build artifacts
clean_build() {
    echo "Cleaning build artifacts..."
    rm -rf "$OUTPUT_DIR" "$PACKAGE_DIR"
    cargo clean
}

# Function to build project
build_project() {
    echo "Building $PROJECT_NAME (v$VERSION)..."
    cargo build --release
}

# Function to run tests
run_tests() {
    echo "Running tests..."
    cargo test
}

# Function to verify YARA rules
verify_yara_rules() {
    echo "Verifying YARA rules..."
    rules_file="$RULES_DIR/rules.yara"
    if [ ! -f "$rules_file" ]; then
        echo "Error: YARA rules file not found at $rules_file"
        exit 1
    fi
    # Placeholder: Use cargo to run a YARA validation check
    cargo run --quiet -- verify-yara "$rules_file"
}

# Function to generate sample memory dump
generate_sample_dump() {
    echo "Generating sample memory dump..."
    dump_file="$PACKAGE_DIR/sample_dump.bin"
    dd if=/dev/urandom of="$dump_file" bs=4K count=1 status=none
}

# Function to package release
package_release() {
    echo "Packaging release..."
    mkdir -p "$PACKAGE_DIR"
    cp "$OUTPUT_DIR/$PROJECT_NAME" "$PACKAGE_DIR/"
    cp -r "$WEB_DIR" "$PACKAGE_DIR/"
    cp -r "$RULES_DIR" "$PACKAGE_DIR/"
    mkdir -p "$PACKAGE_DIR/db"
    generate_sample_dump

    # Create tarball
    tar -C "$PACKAGE_DIR" -czf "$PACKAGE_DIR/$ARCHIVE_NAME" .
    echo "Release packaged at: $PACKAGE_DIR/$ARCHIVE_NAME"
}

# Main execution
if [ "$1" = "--clean" ]; then
    clean_build
    exit 0
fi

echo "Starting build for $PROJECT_NAME (v$VERSION) on $(uname -s)"
check_deps
build_project
run_tests
verify_yara_rules
package_release

echo "Build and packaging completed successfully!"