# Host-side entry points for the LTE testbed container.
#
# Usage:
#   make build              # build the container image
#   make capture NAME=foo   # run an attach scenario, save pcap to captures/
#   make shell              # interactive root shell inside the container
#   make clean              # remove logs/ and captures/ (image kept)

IMAGE       := ran-testbed:latest
REPO_DIR    := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CAPTURES    := $(REPO_DIR)/captures
NAME        ?= legit_attach

# --net=host: srsenb/srsue/Open5GS all bind 127.0.0.x on loopback; sharing the
#   host's loopback keeps the SCTP/GTP/ZMQ ports reachable without bridge NAT.
# --cap-add=NET_ADMIN: tcpdump on lo needs CAP_NET_ADMIN; Open5GS UPF needs it
#   too to create the ogstun TUN interface.
# --device /dev/net/tun: UPF opens /dev/net/tun for the ogstun interface.
# --rm: each capture is a fresh run; no state between invocations.
# -e HOST_UID/HOST_GID: run.py chowns pcap+meta back to the host user on exit
#   so the bind-mounted captures/ stays user-owned (container itself runs as
#   root because srsenb/UPF need it). When invoked under sudo we prefer
#   SUDO_UID/SUDO_GID — `id -u` would otherwise report root and the chown
#   would be a no-op.
# Only captures/ is bind-mounted: logs stay inside the container (--rm wipes
#   them). On failure, run.py prints the last lines of the dying daemon's
#   log to stderr — debugging path matches `docker logs` idiom.
DOCKER_RUN := docker run --rm \
	--net=host \
	--cap-add=NET_ADMIN \
	--device /dev/net/tun \
	--ulimit core=0 \
	-e HOST_UID=$(if $(SUDO_UID),$(SUDO_UID),$(shell id -u)) \
	-e HOST_GID=$(if $(SUDO_GID),$(SUDO_GID),$(shell id -g)) \
	-v $(REPO_DIR)/run.py:/work/run.py:ro \
	-v $(REPO_DIR)/configs:/work/configs:ro \
	-v $(REPO_DIR)/configs/open5gs:/etc/open5gs:ro \
	-v $(CAPTURES):/captures \
	$(IMAGE)

.PHONY: build capture shell clean

build:
	docker build -t $(IMAGE) $(REPO_DIR)

capture: | $(CAPTURES)
	$(DOCKER_RUN) capture $(NAME) --out-dir /captures

shell:
	docker run --rm -it \
		--net=host \
		--cap-add=NET_ADMIN \
		--device /dev/net/tun \
		--ulimit core=0 \
		-v $(REPO_DIR)/run.py:/work/run.py:ro \
		-v $(REPO_DIR)/configs:/work/configs:ro \
		-v $(REPO_DIR)/configs/open5gs:/etc/open5gs:ro \
		-v $(CAPTURES):/captures \
		--entrypoint /bin/bash \
		$(IMAGE)

$(CAPTURES):
	mkdir -p $@

clean:
	rm -rf $(CAPTURES)
