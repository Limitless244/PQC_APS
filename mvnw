#!/bin/sh
# Maven Wrapper launch script for Unix/macOS/Linux
# Generated for PQC-APS project — do not edit manually.
#
# Usage: ./mvnw [maven-goals]
# Example: ./mvnw clean package

set -e

MAVEN_PROJECTBASEDIR="$(dirname "$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")")"

MAVEN_WRAPPER_JAR="$MAVEN_PROJECTBASEDIR/.mvn/wrapper/maven-wrapper.jar"
MAVEN_WRAPPER_PROPERTIES="$MAVEN_PROJECTBASEDIR/.mvn/wrapper/maven-wrapper.properties"

# Read distributionUrl from properties
DISTRIBUTION_URL=$(grep "^distributionUrl" "$MAVEN_WRAPPER_PROPERTIES" | sed 's/distributionUrl=//')

MAVEN_USER_HOME="${MAVEN_USER_HOME:-$HOME/.m2}"
MAVEN_HOME="$MAVEN_USER_HOME/wrapper/dists/$(basename "$DISTRIBUTION_URL" .zip)"

if [ ! -d "$MAVEN_HOME" ]; then
    echo "Downloading Maven from $DISTRIBUTION_URL ..."
    mkdir -p "$MAVEN_HOME"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DISTRIBUTION_URL" -o "$MAVEN_HOME/maven.zip"
    else
        wget -q "$DISTRIBUTION_URL" -O "$MAVEN_HOME/maven.zip"
    fi
    unzip -q "$MAVEN_HOME/maven.zip" -d "$MAVEN_HOME"
    rm "$MAVEN_HOME/maven.zip"
fi

MVN_CMD="$(find "$MAVEN_HOME" -name "mvn" -type f | head -1)"
exec "$MVN_CMD" "$@"
