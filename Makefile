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
# --cap-add=NET_ADMIN: tcpdump on lo needs CAP_NET_ADMIN (or running as root
#   with the inherited cap, which we get inside the container).
# --rm: each capture is a fresh run; no state to keep between invocations
#   (configs and outputs are bind-mounted from the repo).
DOCKER_RUN := docker run --rm \
	--net=host \
	--cap-add=NET_ADMIN \
	-v $(REPO_DIR):/work \
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
		-v $(REPO_DIR):/work \
		-v $(REPO_DIR)/configs/open5gs:/etc/open5gs:ro \
		-v $(CAPTURES):/captures \
		--entrypoint /bin/bash \
		$(IMAGE)

$(CAPTURES):
	mkdir -p $@

clean:
	rm -rf $(REPO_DIR)/logs $(CAPTURES)
