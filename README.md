# Dev Container Features by Rocker Project

A collection of Dev Container Features.

This repository contains a collection of Dev Container Features.

For a detailed explanation of Dev Container Features, please check [the specification](https://containers.dev/implementors/features/) and the [devcontainers' official Development Container Features repository](https://github.com/devcontainers/features).

## Contents

### [`auto-secrets`](auto-secrets-manager/README.md)

Auto-loads environment secrets into DevContainers based on your current git branch with zero configuration.

Automatically manages environment secrets in DevContainers by mapping git branches to environments (main→prod, staging→staging, feature/\*→dev), integrating with popular secret managers like Infisical and Vault, and providing secure caching with tiered access control - all with zero setup beyond adding one line to your devcontainer.json.
