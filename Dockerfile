# syntax=docker/dockerfile:1
#
# Snort 3 multi-platform Alpine image
#
# Platforms:
#   linux/amd64    Vectorscan + LuaJIT
#   linux/arm64    Vectorscan + LuaJIT
#   linux/ppc64le  Vectorscan, no LuaJIT  (no upstream LuaJIT PPC64 backend)
#   linux/arm/v7   AC-BNFA  + LuaJIT
#   linux/386      AC-BNFA  + LuaJIT
#
# Build:
#   docker build --platform linux/amd64 -t snort3:alpine .
#   docker buildx build --platform linux/amd64,linux/arm64,linux/ppc64le,linux/arm/v7,linux/386 \
#     -t yourrepo/snort3:alpine --push .
#
# SNORT_REPO/SNORT_BRANCH point to the arm32 fix branch (snort3/snort3#459, pending merge).
# Switch back to upstream once merged:
#   --build-arg SNORT_REPO=https://github.com/snort3/snort3.git --build-arg SNORT_BRANCH=<tag>
#
# Run:
#   docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
#     -v $(pwd)/snort.lua:/snort3/etc/snort/snort.lua:ro \
#     -v $(pwd)/rules:/snort3/etc/rules:ro \
#     -v snort-logs:/var/log/snort \
#     snort3:alpine -c /snort3/etc/snort/snort.lua -i eth0 -A fast

ARG ALPINE_VERSION=3.21
ARG SNORT_VERSION=3.12.1.0

# Stage 1: build tools and -dev headers, shared by all builder stages
FROM alpine:${ALPINE_VERSION} AS toolchain

ARG TARGETARCH
ARG TARGETVARIANT

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add --update-cache \
        build-base \
        cmake \
        autoconf \
        automake \
        libtool \
        bison \
        flex \
        flex-dev \
        git \
        curl \
        pkgconf \
        python3 \
        libpcap-dev \
        hwloc-dev \
        openssl-dev \
        zlib-dev \
        pcre2-dev \
        xz-dev \
        libdnet-dev \
        libtirpc-dev \
        cpputest

# Vectorscan is only packaged for amd64, arm64, and ppc64le
RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    if [ "$TARGETARCH" = "amd64" ] || \
       [ "$TARGETARCH" = "arm64" ] || \
       [ "$TARGETARCH" = "ppc64le" ]; then \
        apk add --update-cache vectorscan-dev; \
    fi

# Stage 2: LuaJIT and libdaq (not in Alpine packages)
# LuaJIT built from v2.1 branch — fixes CVE-2024-25176/25177/25178 in Alpine's packaged r0.
# ppc64le falls back to the Alpine community port (no upstream LuaJIT PPC64 backend).
FROM toolchain AS deps-builder

ARG TARGETARCH
ARG TARGETVARIANT

RUN if [ "$TARGETARCH" = "amd64" ] || \
       [ "$TARGETARCH" = "arm64" ] || \
       [ "$TARGETARCH" = "arm" ]   || \
       [ "$TARGETARCH" = "386" ];  then \
        git clone --depth 1 --branch v2.1 \
            https://github.com/LuaJIT/LuaJIT.git /tmp/luajit \
     && cd /tmp/luajit \
     && make -j$(nproc) PREFIX=/usr/local \
     && make install PREFIX=/usr/local \
     && rm -rf /tmp/luajit; \
    else \
        apk add --no-cache luajit-dev; \
    fi

RUN git clone --depth 1 https://github.com/snort3/libdaq.git /tmp/libdaq \
 && cd /tmp/libdaq \
 && ./bootstrap \
 && ./configure --prefix=/usr/local \
 && make -j$(nproc) install \
 && rm -rf /tmp/libdaq

# Stage 3: Snort 3 build and unit tests
FROM deps-builder AS snort-builder

ARG SNORT_VERSION
# Defaults to the arm32 SIGBUS fix branch (snort3/snort3#459) until merged upstream.
# Override to switch back: --build-arg SNORT_REPO=https://github.com/snort3/snort3.git --build-arg SNORT_BRANCH=<tag>
ARG SNORT_REPO=https://github.com/ssam18/snort3.git
ARG SNORT_BRANCH=fix/arm32-sigbus-unaligned-ip-access
ARG TARGETARCH

RUN git clone --depth 1 --branch "$SNORT_BRANCH" \
        "$SNORT_REPO" /tmp/snort3

RUN cd /tmp/snort3 \
 && if [ "$TARGETARCH" = "amd64" ] || \
       [ "$TARGETARCH" = "arm64" ] || \
       [ "$TARGETARCH" = "arm" ]   || \
       [ "$TARGETARCH" = "386" ];  then \
        ./configure_cmake.sh \
            --prefix=/snort3 \
            --build-type=MinSizeRel \
            --without-libml \
            --disable-docs \
            --disable-gdb \
            --enable-unit-tests \
            --with-luajit-includes=/usr/local/include/luajit-2.1 \
            --with-luajit-libraries=/usr/local/lib; \
    else \
        ./configure_cmake.sh \
            --prefix=/snort3 \
            --build-type=MinSizeRel \
            --without-libml \
            --disable-docs \
            --disable-gdb \
            --enable-unit-tests; \
    fi \
 && cd build \
 && make -j$(nproc) install \
 && make -j$(nproc) check \
 && rm -rf /tmp/snort3

RUN find /snort3/bin /snort3/lib /usr/local/lib -type f \
        \( -name "*.so*" -o -name "snort" \) \
        -exec strip --strip-unneeded {} + 2>/dev/null || true

# Stage 4: minimal runtime image, no build tools or headers
FROM alpine:${ALPINE_VERSION}

ARG SNORT_VERSION
ARG TARGETARCH

LABEL org.opencontainers.image.title="snort3" \
      org.opencontainers.image.description="Snort 3 IDS - minimal Alpine image" \
      org.opencontainers.image.version="${SNORT_VERSION}" \
      org.opencontainers.image.source="https://github.com/snort3/snort3" \
      org.opencontainers.image.base.name="alpine:3.21"

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add --update-cache \
        bash \
        libpcap \
        hwloc \
        libssl3 \
        libcrypto3 \
        zlib \
        pcre2 \
        xz-libs \
        libdnet \
        libtirpc \
        libuuid \
        libstdc++ \
        libgcc

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    if [ "$TARGETARCH" = "amd64" ] || \
       [ "$TARGETARCH" = "arm64" ] || \
       [ "$TARGETARCH" = "ppc64le" ]; then \
        apk add --update-cache vectorscan; \
    fi

# source-built LuaJIT lands in /usr/local/lib; Alpine package lands in /usr/lib — copy whichever
RUN --mount=type=bind,from=snort-builder,source=/usr/local/lib,target=/build/local/lib \
    --mount=type=bind,from=snort-builder,source=/usr/lib,target=/build/usr/lib \
    find /build/local/lib /build/usr/lib -name 'libluajit-5.1.so*' \
         -exec cp -P {} /usr/local/lib/ \; 2>/dev/null || true

COPY --link --from=snort-builder /usr/local/lib/libdaq.so*  /usr/local/lib/
COPY --link --from=snort-builder /usr/local/lib/daq/        /usr/local/lib/daq/
COPY --link --from=snort-builder /snort3 /snort3

ENV LD_LIBRARY_PATH=/usr/local/lib:/snort3/lib
ENV PATH=/snort3/bin:$PATH

RUN adduser -D -h /home/snorty snorty \
 && mkdir -p /var/log/snort /snort3/etc/rules \
 && chown -R snorty:snorty /var/log/snort /snort3/etc/rules

VOLUME ["/snort3/etc/rules", "/var/log/snort"]

USER snorty
WORKDIR /home/snorty

ENTRYPOINT ["snort"]
CMD ["--version"]
