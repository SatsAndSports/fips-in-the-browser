.DEFAULT_GOAL := all
.PHONY: all build wasm serve v86-assets clean-v86

all: build v86-assets

V86_BASE := https://copy.sh/v86
V86_DIR := www/v86

build wasm:
	wasm-pack build --target web

serve:
	python3 -m http.server 9000

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

clean-v86:
	rm -rf $(V86_DIR)
