# LTE testbed: Open5GS 4G core + srsRAN_4G (srsenb + srsue) over ZMQ.
#
# Multi-stage build:
#   builder  — compiles srsenb/srsue from a pinned srsRAN_4G ref.
#   runtime  — Open5GS via PPA, MongoDB via upstream repo, plus the two
#              binaries copied out of builder. No compilers, no source.
#
# Layer ordering inside each stage is most-stable → most-volatile so editing
# a late line doesn't invalidate the expensive layers. run.py and the config
# files are bind-mounted at /work — they are NEVER copied in — so editing
# them never invalidates any image layer.
#
# Pins:
#   FROM image:    ubuntu:24.04 (Noble)
#   srsRAN_4G:     release_23_11        (override: --build-arg SRSRAN_REF=...)
#   Open5GS:       2.7.7~noble          (override: --build-arg OPEN5GS_VERSION=...)
#   MongoDB:       7.0                  (override: --build-arg MONGO_VERSION=...)

# ---------------------------------------------------------------------------
# Stage 1: builder — compile srsRAN_4G
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential \
        cmake \
        pkg-config \
        libfftw3-dev \
        libmbedtls-dev \
        libsctp-dev \
        libconfig++-dev \
        libboost-program-options-dev \
        libzmq3-dev \
    && rm -rf /var/lib/apt/lists/*

ARG SRSRAN_REF=release_23_11
RUN git clone --depth 1 --branch ${SRSRAN_REF} \
        https://github.com/srsran/srsRAN_4G.git /src/srsRAN_4G

WORKDIR /src/srsRAN_4G/build
RUN cmake -DCMAKE_BUILD_TYPE=Release .. \
    && make -j"$(nproc)" srsenb srsue \
    && install -Dm755 srsenb/src/srsenb /out/srsenb \
    && install -Dm755 srsue/src/srsue   /out/srsue

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    PYTHONUNBUFFERED=1

# Base runtime deps + the *runtime* libs srsenb/srsue link against (no -dev).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        gnupg \
        curl \
        software-properties-common \
        iproute2 \
        iputils-ping \
        tcpdump \
        python3 \
        libfftw3-double3 \
        libmbedtls14t64 \
        libsctp1 \
        libconfig++9v5 \
        libboost-program-options1.83.0 \
        libzmq5 \
    && rm -rf /var/lib/apt/lists/*

# MongoDB upstream repo (Ubuntu 24.04 has no official mongodb-server package).
# Pinned via MONGO_VERSION; jammy repo is the closest supported codename.
ARG MONGO_VERSION=7.0
RUN curl -fsSL https://www.mongodb.org/static/pgp/server-${MONGO_VERSION}.asc \
        | gpg --dearmor -o /usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg \
    && echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/${MONGO_VERSION} multiverse" \
        > /etc/apt/sources.list.d/mongodb-org-${MONGO_VERSION}.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        mongodb-org-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/mongodb /var/log/mongodb

# Open5GS PPA, pinned exact version.
ARG OPEN5GS_VERSION=2.7.7~noble
RUN add-apt-repository -y ppa:open5gs/latest \
    && apt-get update && apt-get install -y --no-install-recommends \
        open5gs=${OPEN5GS_VERSION} \
    && rm -rf /var/lib/apt/lists/*

# Pull srsRAN binaries out of builder. This is the only line that "depends on"
# the builder stage, so the runtime layer cache is preserved across srsRAN
# rebuilds as long as runtime deps don't move.
COPY --from=builder /out/srsenb /usr/local/bin/srsenb
COPY --from=builder /out/srsue  /usr/local/bin/srsue

# Stamp pin versions into the image so run.py can record them into meta JSON.
ENV SRSRAN_REF=${SRSRAN_REF} \
    OPEN5GS_VERSION=${OPEN5GS_VERSION} \
    MONGO_VERSION=${MONGO_VERSION}

RUN mkdir -p /var/log/open5gs /work
WORKDIR /work

ENTRYPOINT ["python3", "/work/run.py"]
CMD ["--help"]
