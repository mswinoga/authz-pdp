ARG BASE_IMAGE=busybox:latest
FROM ${BASE_IMAGE}

COPY --chown=1000:1000 bin/pdp-server /pdp-server
USER 1000

EXPOSE 9191

ENTRYPOINT ["/pdp-server"]
