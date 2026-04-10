.DEFAULT_GOAL := all
.PHONY: all build wasm serve v86-assets clean-v86 docs

DOCS_DIR := ../docs

all: build v86-assets

V86_BASE := https://copy.sh/v86
V86_DIR := www/v86

build wasm:
	wasm-pack build --target web --out-dir www/pkg

serve:
	python3 -m http.server 9000 -d www

$(V86_DIR)/build/libv86.js:
	mkdir -p $(V86_DIR)/build
	curl -L --fail -o $@ $(V86_BASE)/build/libv86.js

$(V86_DIR)/build/v86.wasm:
	mkdir -p $(V86_DIR)/build
	curl -L --fail -o $@ $(V86_BASE)/build/v86.wasm

$(V86_DIR)/bios/seabios.bin:
	mkdir -p $(V86_DIR)/bios
	curl -L --fail -o $@ $(V86_BASE)/bios/seabios.bin

$(V86_DIR)/bios/vgabios.bin:
	mkdir -p $(V86_DIR)/bios
	curl -L --fail -o $@ $(V86_BASE)/bios/vgabios.bin

$(V86_DIR)/images/buildroot-bzimage68.bin:
	mkdir -p $(V86_DIR)/images
	curl -L --fail -o $@ https://i.copy.sh/buildroot-bzimage68.bin

v86-assets: \
	$(V86_DIR)/build/libv86.js \
	$(V86_DIR)/build/v86.wasm \
	$(V86_DIR)/bios/seabios.bin \
	$(V86_DIR)/bios/vgabios.bin \
	$(V86_DIR)/images/buildroot-bzimage68.bin

docs: build v86-assets
	rm -rf $(DOCS_DIR)
	mkdir -p $(DOCS_DIR)
	cp www/index.html $(DOCS_DIR)/
	cp -r www/pkg $(DOCS_DIR)/
	cp -r www/v86 $(DOCS_DIR)/
	@echo "docs/ ready for GitHub Pages"

clean-v86:
	rm -rf $(V86_DIR)
