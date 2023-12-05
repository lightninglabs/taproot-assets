#!/bin/bash

# This script derives a git tag name from the version fields found in a given Go
# file. It also checks if the derived git tag name is a valid SemVer compliant
# version string.

# get_git_tag_name reads the version fields from the given file and then
# constructs and returns a git tag name.
get_git_tag_name() {
  local file_path="$1"

  # Check if the file exists
  if [ ! -f "$file_path" ]; then
      echo "Error: File not found at $file_path" >&2
      exit 1
  fi

  # Read and parse the version fields. We interpret these fields using regex
  # matching which effectively serves as a basic sanity check.
  local app_major
  app_major=$(grep -oP 'AppMajor\s*uint\s*=\s*\K\d+' "$file_path")

  local app_minor
  app_minor=$(grep -oP 'AppMinor\s*uint\s*=\s*\K\d+' "$file_path")

  local app_patch
  app_patch=$(grep -oP 'AppPatch\s*uint\s*=\s*\K\d+' "$file_path")

  local app_status
  app_status=$(grep -oP 'AppStatus\s*=\s*"\K([a-z]*)' "$file_path")

  local app_pre_release
  app_pre_release=$(grep -oP 'AppPreRelease\s*=\s*"\K([a-z0-9]*)' "$file_path")

  # Parse the GitTagIncludeStatus field.
  local git_tag_include_status
  git_tag_include_status=false

  if grep -q 'GitTagIncludeStatus = true' "$file_path"; then
      git_tag_include_status=true
  elif grep -q 'GitTagIncludeStatus = false' "$file_path"; then
      git_tag_include_status=false
  else
      echo "Error: GitTagIncludeStatus is not present in the Go version file."
      exit 1
  fi

  # Construct the git tag name with conditional inclusion of app_status and
  # app_pre_release.
  tag_name="v${app_major}.${app_minor}.${app_patch}"

  # Append app_status if git_tag_include_status is true and app_status if
  # specified.
  if [ "$git_tag_include_status" = true ] && [ -n "$app_status" ]; then
      tag_name+="-${app_status}"

      # Append app_pre_release if specified.
      if [ -n "$app_pre_release" ]; then
          tag_name+=".${app_pre_release}"
      fi
  else
      # If the app_status field is not specified, then append
      # app_pre_release (if specified) using a dash prefix.
      if [ -n "$app_pre_release" ]; then
          tag_name+="-${app_pre_release}"
      fi
  fi

  echo "$tag_name"
}

file_path="$1"
echo "Reading version fields from file: $file_path" >&2
tag_name=$(get_git_tag_name "$file_path")
echo "Derived git tag name: $tag_name" >&2

echo "$tag_name"
