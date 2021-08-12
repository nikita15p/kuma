ENVOY_IMPORTS := ./pkg/xds/envoy/imports.go
PROTO_DIR := ./pkg/config

protoc_search_go_packages := \
	github.com/golang/protobuf@$(GOLANG_PROTOBUF_VERSION) \
	github.com/envoyproxy/protoc-gen-validate@$(PROTOC_PGV_VERSION) \

protoc_search_go_paths := $(foreach go_package,$(protoc_search_go_packages),--proto_path=$(GOPATH_DIR)/pkg/mod/$(go_package))

# Protobuf-specifc configuration
PROTOC_GO := protoc \
	--proto_path=$(PROTOBUF_WKT_DIR)/include \
	--proto_path=./api \
	--proto_path=. \
	$(protoc_search_go_paths) \
	--go_opt=paths=source_relative \
	--go_out=plugins=grpc,Msystem/v1alpha1/datasource.proto=github.com/kumahq/kuma/api/system/v1alpha1:.

.PHONY: clean/proto
clean/proto: ## Dev: Remove auto-generated Protobuf files
	find $(PROTO_DIR) -name '*.pb.go' -delete
	find $(PROTO_DIR) -name '*.pb.validate.go' -delete

.PHONY: generate
generate:  ## Dev: Run code generators
generate: clean/proto protoc/pkg/config/app/kumactl/v1alpha1 protoc/pkg/test/apis/sample/v1alpha1 protoc/plugins resources/type generate/deepcopy

.PHONY: resources/type
resources/type:
	$(GO_RUN) ./tools/resource-gen.go -generator type

.PHONY: protoc/pkg/config/app/kumactl/v1alpha1
protoc/pkg/config/app/kumactl/v1alpha1:
	$(PROTOC_GO) pkg/config/app/kumactl/v1alpha1/*.proto

.PHONY: protoc/pkg/test/apis/sample/v1alpha1
protoc/pkg/test/apis/sample/v1alpha1:
	$(PROTOC_GO) pkg/test/apis/sample/v1alpha1/*.proto

.PHONY: protoc/plugins
protoc/plugins:
	$(PROTOC_GO) pkg/plugins/ca/provided/config/*.proto
	$(PROTOC_GO) pkg/plugins/ca/builtin/config/*.proto

KUMA_GUI_GIT=https://github.com/kumahq/kuma-gui.git
KUMA_GUI_VERSION=master
KUMA_GUI_FOLDER=app/kuma-ui/pkg/resources/data
KUMA_GUI_WORK_FOLDER=app/kuma-ui/data/work

.PHONY: upgrade/gui
upgrade/gui:
	rm -rf $(KUMA_GUI_WORK_FOLDER); \
	git clone --depth 1 -b $(KUMA_GUI_VERSION) https://github.com/kumahq/kuma-gui.git $(KUMA_GUI_WORK_FOLDER); \
	pushd $(KUMA_GUI_WORK_FOLDER) && yarn install && yarn build && popd; \
	rm -rf $(KUMA_GUI_FOLDER) && mv $(KUMA_GUI_WORK_FOLDER)/dist/ $(KUMA_GUI_FOLDER); \
	rm -rf $(KUMA_GUI_WORK_FOLDER); \

.PHONY: generate/envoy-imports
generate/envoy-imports:
	echo 'package envoy\n' > ${ENVOY_IMPORTS}
	echo '// Import all Envoy packages so protobuf are registered and are ready to used in functions such as MarshalAny.' >> ${ENVOY_IMPORTS}
	echo '// This file is autogenerated. run "make generate/envoy-imports" to regenerate it after go-control-plane upgrade' >> ${ENVOY_IMPORTS}
	echo 'import (' >> ${ENVOY_IMPORTS}
	go list github.com/envoyproxy/go-control-plane/... | grep "github.com/envoyproxy/go-control-plane/envoy/" | awk '{printf "\t_ \"%s\"\n", $$1}' >> ${ENVOY_IMPORTS}
	echo ')' >> ${ENVOY_IMPORTS}

.PHONY: generate/deepcopy
generate/deepcopy:
	$(MAKE) -C pkg/plugins/resources/k8s/native generate
