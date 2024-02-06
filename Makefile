BUILD_DIR = build
MESON_DIR = build/meson-src
COMP_FILE = compile_commands.json

setup: install_deps configure

install_deps:
	conan install . --output-folder=$(BUILD_DIR) --build=missing

configure:
	meson setup --native-file $(BUILD_DIR)/conan_meson_native.ini . $(MESON_DIR)

compile:
	cp $(MESON_DIR)/$(COMP_FILE) .
	sed -i 's/g++/clangd/g' $(COMP_FILE)
	meson compile -C $(MESON_DIR)

run:
	./$(MESON_DIR)/runner

clean:
	rm $(COMP_FILE)
	rm -rf $(BUILD_DIR)
	rm -rf .cache
