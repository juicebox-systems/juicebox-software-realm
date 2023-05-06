FROM golang:1.20

ARG PROVIDER=memory
ENV PROVIDER=$PROVIDER

COPY . /app

WORKDIR /app

RUN go mod download

RUN CGO_ENABLED=0 go build -o /jb-sw-realm

EXPOSE 443

CMD /jb-sw-realm -id ${REALM_ID} -provider ${PROVIDER} -port 443
