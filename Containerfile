# Containerised toolchain for the ethereum-sdk test suite.
#
# Bundles everything the host deliberately lacks: forge/anvil/cast (Foundry)
# for the Solidity suite, and Node for the jest TS suite (unit + anvil-backed
# integration). node_modules is NOT installed here — it is bind-mounted from
# the host by ./run, because the @midl/* devDeps are file: links to a sibling
# repo that need not exist for the test suite. Solidity deps are fetched at
# runtime by `./run setup` (forge soldeer install) into the mounted repo.
#
# Build:  ./run build
# Use:    ./run test | ./run test-all | ./run shell
FROM node:20-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# curl: foundryup installer. git+openssh-client: soldeer git deps (the private
# gitlab hashsigs-solidity dep is fetched over SSH). jq: storage-layout target.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        ca-certificates \
        openssh-client \
        jq \
    && rm -rf /var/lib/apt/lists/*

# Foundry installed system-wide so any runtime UID can exec it. solc itself is
# fetched on demand at first build into $HOME (a bind-mounted cache via ./run),
# so it persists across container runs rather than re-downloading each time.
ENV FOUNDRY_DIR=/opt/foundry
ENV PATH=/opt/foundry/bin:$PATH
ARG FOUNDRY_VERSION=stable
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
    && foundryup --install "${FOUNDRY_VERSION}" \
    && chmod -R a+rx /opt/foundry/bin \
    && forge --version && anvil --version

WORKDIR /work
CMD ["bash"]
