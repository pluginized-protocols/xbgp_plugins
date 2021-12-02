FROM seahorn/seahorn-llvm10:nightly

USER root

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install libjson-c-dev -y

# Switch back to normal image user
USER usea