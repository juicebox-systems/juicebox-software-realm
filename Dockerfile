FROM golang:1.20

ARG PROVIDER=memory
ENV PROVIDER=$PROVIDER

ENV LETS_ENCRYPT_CACHE="/var/cache/letsencrypt"

VOLUME [ "${LETS_ENCRYPT_CACHE}" ]

COPY . /app

WORKDIR /app

RUN go mod download

RUN CGO_ENABLED=0 go build -o /jb-sw-realm

EXPOSE 443

CMD /jb-sw-realm -port 443 ${DISABLE_TLS:+-disable-tls}
