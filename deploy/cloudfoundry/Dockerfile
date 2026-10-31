# Build the standard image first, then add the CF deployment configuration.
# Example: docker build --build-arg PROOFVISOR_IMAGE=proofvisor-base:local \
#   -f deploy/cloudfoundry/Dockerfile -t registry.example.com/proofvisor:cf .
ARG PROOFVISOR_IMAGE=proofvisor-base:local
FROM ${PROOFVISOR_IMAGE}
COPY --chown=65532:65532 deploy/cloudfoundry/harness.toml /app/config/harness.cloudfoundry.toml
ENV PV_CONFIG=/app/config/harness.cloudfoundry.toml
