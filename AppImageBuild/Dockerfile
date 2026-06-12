FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential wget file desktop-file-utils \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libncursesw5-dev libffi-dev liblzma-dev tk-dev uuid-dev \
    libxcb-xinerama0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
    libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxkbcommon-x11-0

ARG PYVER=3.10.14
RUN wget -q https://www.python.org/ftp/python/${PYVER}/Python-${PYVER}.tgz && \
    tar xf Python-${PYVER}.tgz && cd Python-${PYVER} && \
    ./configure --prefix=/opt/python310 --enable-shared --enable-optimizations \
                LDFLAGS="-Wl,-rpath,/opt/python310/lib" && \
    make -j"$(nproc)" && make install && \
    cd / && rm -rf Python-${PYVER}*
ENV PATH=/opt/python310/bin:$PATH
