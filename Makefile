SHELL := /bin/sh

CROSS_PREFIX ?= z80-none-elf-
AS := $(CROSS_PREFIX)as
LD := $(CROSS_PREFIX)ld
OBJCOPY := $(CROSS_PREFIX)objcopy
CC ?= cc

ASFLAGS ?= -march=z80+full
CFLAGS ?= -O2 -std=c99 -Wall -Wextra
LDFLAGS ?=

BUILD_DIR ?= build
PACKER := $(BUILD_DIR)/tools/mk82b
TEMPLATE := reference/CRASH.82B

INSTALLERS := \
	$(BUILD_DIR)/release/BURN-15.0-16.0-17.0-18.0.82B \
	$(BUILD_DIR)/release/BURN-19.0.82B \
	$(BUILD_DIR)/release/BURN-19.006.82B

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

.PHONY: all installers toolchain clean

all: installers

installers: $(INSTALLERS)

$(PACKER): tools/mk82b.c
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -o "$@" "$<"

define PROFILE_RULES
$(BUILD_DIR)/$(1)/burn.o: src/burn.s
	@mkdir -p "$$(@D)"
	$(AS) $(ASFLAGS) --defsym BURN_ROM_PROFILE=$(2) -alhnd=$(BUILD_DIR)/$(1)/burn.lst -o "$$@" "$$<"

$(BUILD_DIR)/$(1)/burn.elf: $(BUILD_DIR)/$(1)/burn.o src/burn.ld
	$(LD) $(LDFLAGS) -T src/burn.ld -Map $(BUILD_DIR)/$(1)/burn.map -o "$$@" "$$<"

$(BUILD_DIR)/$(1)/burn.bin: $(BUILD_DIR)/$(1)/burn.elf
	$(OBJCOPY) -O binary -j .text "$$<" "$$@"

$(BUILD_DIR)/release/$(3): $(BUILD_DIR)/$(1)/burn.bin $(PACKER) $(TEMPLATE)
	@mkdir -p "$$(@D)"
	$(PACKER) --template $(TEMPLATE) --native "$$<" --output "$$@" --profile $(4) --comment "$(5)"
endef

$(eval $(call PROFILE_RULES,15.0-18.0,1518,BURN-15.0-16.0-17.0-18.0.82B,15.0-18.0,BuRN shell for TI-82 ROMs 15.0-18.0))
$(eval $(call PROFILE_RULES,19.0,1900,BURN-19.0.82B,19.0,BuRN clean-room shell for TI-82 ROM 19.0))
$(eval $(call PROFILE_RULES,19.006,19006,BURN-19.006.82B,19.006,BuRN clean-room shell for TI-82 ROM 19.006))

toolchain:
	@$(AS) --version | sed -n '1p'
	@$(LD) --version | sed -n '1p'
	@$(OBJCOPY) --version | sed -n '1p'
	@$(CC) --version | sed -n '1p'

clean:
	rm -rf -- "$(BUILD_DIR)"
