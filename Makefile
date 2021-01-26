.PHONY: all build tag clean run

all: build tag

# Increment this number whenever this package changes, using
# Semantic Versioning conventions.

RELEASE_VERSION=0.0.4

# HAProxy and 3rd party library versions to build

IMAGE_TAG=rblx$(RELEASE_VERSION)

REGISTRY ?= cloud-registry.simulpong.com

build: Dockerfile
	docker build -t stick_table_exporter:$(IMAGE_TAG) \
	  .

tag:
		docker tag stick_table_exporter:$(IMAGE_TAG) $(REGISTRY)/stick_table_exporter:$(IMAGE_TAG)

run:
		docker run --rm -p 8000:8000 \
		--name stick_table_exporter stick_table_exporter:$(IMAGE_TAG)

push:
		docker push $(REGISTRY)/stick_table_exporter:$(IMAGE_TAG)

clean:
	-docker rmi -f $(REGISTRY)/stick_table_exporter:$(IMAGE_TAG)
	-docker rmi -f stick_table_exporter:$(IMAGE_TAG)