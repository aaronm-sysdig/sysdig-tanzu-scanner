#!/bin/bash

# Location of the file storing the current version
VERSION_FILE="./VERSION"

# Read the current version
if [ ! -f $VERSION_FILE ]; then
    echo "0.0.0" > $VERSION_FILE
fi

current_version=$(cat $VERSION_FILE)

# Break the version number into major, minor, and patch
IFS='.' read -r major minor patch <<< "$current_version"

# Increment the patch number
patch=$((patch + 1))

# Combine them back
new_version="$major.$minor.$patch"

# Write the new version back to the file
echo $new_version > $VERSION_FILE

# Output the new version for use in other scripts (like GitHub Actions)
echo $new_version
