FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      g++ make libpcap-dev libyaml-cpp-dev libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile .
COPY src ./src
RUN make -j"$(nproc)"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap0.8 libyaml-cpp0.7 libssl3 curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/net_sensor /usr/local/bin/net_sensor
COPY forward.sh /usr/local/bin/forward.sh
ENTRYPOINT ["/usr/local/bin/forward.sh"]
