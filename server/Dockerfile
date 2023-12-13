FROM golang:1.21 AS build
WORKDIR /go/src
COPY . .

RUN make server

FROM scratch AS runtime
COPY --from=build /go/src/server ./
ENTRYPOINT ["./server"]
