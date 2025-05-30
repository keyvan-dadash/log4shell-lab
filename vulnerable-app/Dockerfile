FROM ubuntu:22.04 AS ebpf-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \             
      clang llvm \                  
      libelf-dev pkg-config \       
      libbpf-dev \                  
      linux-libc-dev \              
      linux-headers-generic \ 
      binutils \
    && rm -rf /var/lib/apt/lists/*

# fix the asm/ symlink
RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

WORKDIR /src
COPY runtime/filter.c .
COPY runtime/loader.c .

RUN clang -O2 -target bpf -g -c filter.c -o filter.o

RUN clang -O2 loader.c -static -o loader \
    -lbpf -lelf -lz -pthread

FROM openjdk:11-slim

# Install bpftrace 
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bpftrace \ 
      bpfcc-tools \
      clang \               
      llvm \
      libelf-dev \ 
      pkg-config \
      libbpf-dev \
      linux-libc-dev \
      linux-headers-generic \ 
      bpftool libelf1 \
    && rm -rf /var/lib/apt/lists/*

# Copy loader + Java app
COPY load-ebpf.sh /load-ebpf.sh
COPY pid_filter_client.sh /pid_filter_client.sh
RUN chmod +x /pid_filter_client.sh
RUN chmod +x /load-ebpf.sh

COPY build/libs/vulnerable-app-0.0.1-SNAPSHOT.jar /vulnerable-app.jar

COPY --from=ebpf-builder /src/filter.o /filter.o
COPY --from=ebpf-builder /src/loader    /loader

EXPOSE 8080

ENTRYPOINT ["/load-ebpf.sh"]

