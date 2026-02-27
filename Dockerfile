FROM gcr.io/distroless/static-debian12

COPY bin/pdp /pdp
RUN chown 1000:1000 /pdp
USER 1000

EXPOSE 9191

ENTRYPOINT ["/pdp"]
