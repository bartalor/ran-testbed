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
# them never invalidates any image layer. A copy of run.py IS baked in as a
# fallback so the image is runnable without a bind mount; the bind mount
# wins when present.
#
# Runs as root by design: srsenb opens raw sockets / ZMQ, the Open5GS UPF
# creates ogstun via /dev/net/tun, and tcpdump on lo needs CAP_NET_ADMIN.
# Dropping privileges mid-process is out of scope for a throwaway testbed.
# Mitigations live at the docker run boundary: --rm, --ulimit core=0,
# explicit bind mounts (no -v $REPO:/work).
#
# Pins:
#   FROM image:    ubuntu:24.04 (Noble)
#   srsRAN_4G:     release_23_11        (override: --build-arg SRSRAN_REF=...)
#   Open5GS:       2.7.7~noble          (override: --build-arg OPEN5GS_VERSION=...)
#   MongoDB:       7.0                  (override: --build-arg MONGO_VERSION=...)
#
# Reproducibility note: apt indexes are NOT snapshot-pinned. Two rebuilds
# months apart may pull different patch versions of runtime libs
# (libfftw3-single3, libsctp1, ...). For bit-exact reproducibility, switch
# to snapshot.ubuntu.com — adequate for a research testbed as-is.

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

# gcc 13 + libstdc++ raises false-positive -Warray-bounds / -Wstringop-overflow
# in srsenb's rrc_mobility.cc (std::copy over small fixed-size buffers).
# release_23_11 builds with -Werror, so demote those two to warnings.
#
# `make install` puts binaries in /usr/local/bin and the shared libs srsenb
# dlopens (libsrsran_rf.so etc.) in /usr/local/lib, with the canonical
# .so → .so.MAJOR → .so.X.Y.Z symlink trio. We stage the install tree under
# /out so the runtime stage gets one COPY for everything; trusting upstream's
# install target is the canonical multi-stage idiom (vs. curating the build
# tree by hand, which couples this Dockerfile to upstream's internal layout).
WORKDIR /src/srsRAN_4G/build
RUN cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_CXX_FLAGS="-Wno-error=array-bounds -Wno-error=stringop-overflow -Wno-error=maybe-uninitialized" \
        .. \
    && make -j"$(nproc)" srsenb srsue \
    && DESTDIR=/out make install

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
        libfftw3-single3 \
        libmbedtls14t64 \
        libsctp1 \
        libconfig++9v5 \
        libboost-program-options1.83.0 \
        libzmq5 \
    && rm -rf /var/lib/apt/lists/*

# MongoDB upstream repo (Ubuntu 24.04 has no official mongodb-server package).
# Pinned via MONGO_VERSION. We point at the `jammy` (22.04) MongoDB repo
# because there is no `noble` (24.04) repo published by MongoDB Inc. yet;
# the jammy binaries run fine on noble. Do NOT "fix" this to `noble` — the
# URL 404s. Revisit when MongoDB ships a noble repo.
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

# Pull the srsRAN install tree (binaries + libsrsran_*.so + symlinks) out of
# builder. This is the only line that "depends on" the builder stage, so the
# runtime layer cache is preserved across srsRAN rebuilds as long as runtime
# deps don't move. ldconfig refreshes the linker cache so the libs are
# findable. The install tree carries a handful of dev-only files (headers,
# .a, .cmake, .pc, helper shell scripts) — roughly 10–20 MB in a 1.5 GB
# image, not worth curating around upstream's contract.
COPY --from=builder /out/usr/local/ /usr/local/
RUN ldconfig

# Stamp pin versions into the image so run.py can record them into meta JSON.
# SRSRAN_REF is redeclared here because ARGs don't cross stages — without
# this redeclaration the ENV would expand to empty in the runtime image.
# Must match the builder-stage default; --build-arg overrides both at once.
ARG SRSRAN_REF=release_23_11
ENV SRSRAN_REF=${SRSRAN_REF} \
    OPEN5GS_VERSION=${OPEN5GS_VERSION} \
    MONGO_VERSION=${MONGO_VERSION}

RUN mkdir -p /var/log/open5gs /work
WORKDIR /work

# Baked-in fallback so the image is runnable standalone. Production
# invocation (via the repo's Makefile) bind-mounts the current run.py
# read-only over this path — the mount wins. Keep the COPY last so edits
# to run.py invalidate only this final layer.
COPY run.py /work/run.py

# OCI image metadata — surfaces in `docker inspect`, registry UIs, etc.
# `source` is intentionally omitted: this repo has no canonical remote.
# Add it (and a license) before any registry push.
LABEL org.opencontainers.image.title="ran-testbed" \
      org.opencontainers.image.description="LTE testbed: Open5GS 4G core + srsRAN_4G (srsenb+srsue) over ZMQ, with attach capture."

ENTRYPOINT ["python3", "/work/run.py"]
CMD ["--help"]
