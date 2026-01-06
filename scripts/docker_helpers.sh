#!/bin/bash

# docker_helpers.sh: Common Docker/Podman detection and configuration
#
# This script should be sourced by other scripts that need to run Docker or
# Podman commands. It sets up the DOCKER variable and user_args array based
# on whether Docker or Podman is being used.
#
# Usage:
#   source scripts/docker_helpers.sh
#   "$DOCKER" run "${user_args[@]}" ...

# Use docker by default; allow overrides and detect podman wrapper.
DOCKER=${DOCKER:-docker}
user_args=(--user "$UID:$(id -g)")
if "$DOCKER" --version 2>/dev/null | grep -qi podman; then
	user_args=(--user=0:0)
fi
