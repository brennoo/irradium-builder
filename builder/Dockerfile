FROM --platform=$BUILDPLATFORM alpine:latest AS bootstrap
ARG ARCH=riscv64
ARG DISTR_VERSION=3.8
ENV ARCH=${ARCH} \
    DISTR_VERSION=${DISTR_VERSION}
RUN apk add --no-cache python3 libarchive-tools pax-utils ca-certificates signify
COPY bootstrap.py /tmp/bootstrap.py
RUN python3 /tmp/bootstrap.py

FROM scratch
COPY --from=bootstrap /rootfs/ /
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LC_ALL="C.UTF-8"
RUN ldconfig && update-ca-certificates --fresh 2>/dev/null || true
WORKDIR /usr/ports
CMD ["/bin/bash"]
