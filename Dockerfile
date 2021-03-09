FROM alpine:3.6 as alpine
RUN apk add -U --no-cache ca-certificates
RUN cat /etc/passwd | grep nobody > passwd.nobody

FROM scratch
WORKDIR /
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=alpine /passwd.nobody /etc/passwd
COPY config.yaml /etc/grafana-datasource-auth-proxy/config.yaml
COPY grafana-datasource-auth-proxy /grafana-datasource-auth-proxy
USER nobody
ENTRYPOINT ["/grafana-datasource-auth-proxy"]
