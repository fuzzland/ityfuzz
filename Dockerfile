FROM rust:buster as run_environment
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-venv libz3-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --upgrade pip
RUN mkdir /bins

FROM run_environment as build_environment
RUN apt-get update && apt-get install -y clang pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*

FROM build_environment as builder
WORKDIR /builder

COPY Cargo.toml .
COPY rust-toolchain.toml .
COPY src ./src
COPY benches ./benches

# build offchain binary
RUN cargo build --release
RUN cp target/release/ityfuzz /bins/cli_offchain

# build onchain binary
RUN sed -i -e 's/"cmp"/"cmp","flashloan_v2"/g' ./Cargo.toml
RUN cargo build --release
RUN cp target/release/ityfuzz /bins/cli_onchain

RUN sed -i -e 's/"deployer_is_attacker"/"print_logs"/g' ./Cargo.toml
RUN sed -i -e 's/"print_txn_corpus",//g' ./Cargo.toml
RUN sed -i -e 's/"full_trace",//g' ./Cargo.toml
RUN cargo build --release
RUN cp target/release/ityfuzz /bins/cli_print_logs

FROM run_environment
WORKDIR /app
COPY --from=builder /bins /bins

WORKDIR /bins
COPY tests /bins/tests

EXPOSE 8000


