OPENSDK ?= ../esp-open-sdk
PATH := $(OPENSDK)/xtensa-lx106-elf/bin:$(PATH)
export PATH

# Output directors to store intermediate compiled files relative to the
# project directory
BUILD_BASE	= build
FW_BASE		= firmware

# Base directory for the compiler. Needs a / at the end; if not set it'll use
# the tools that are in the PATH.
XTENSA_TOOLS_ROOT ?=
export XTENSA_TOOLS_ROOT

# base directory of the ESP8266 SDK package, absolute
SDK_BASE	?= $(OPENSDK)/sdk
export SDK_BASE

#Esptool.py path and port
#ESPTOOL		?= $(XTENSA_TOOLS_ROOT)esptool.py
ESPTOOL		?= esptool/esptool.py
ESPPORT		?= /dev/ttyUSB0
ESPBAUD		?= 460800


# name for the target project
TARGET		= esptemplate

# which modules (subdirectories) of the project to include in compiling
MODULES		= src
EXTRA_INCDIR	= include

# libraries used in this project, mainly provided by the SDK
LIBS		= c gcc hal phy pp net80211 lwip wpa main

# compiler flags using during compilation of source files
CFLAGS		= -Os -ggdb -std=c99 -Werror -Wpointer-arith -Wundef -Wall \
		-Wl,-EL -fno-inline-functions -nostdlib -mlongcalls \
		-mtext-section-literals  -D__ets__ -DICACHE_FLASH \
		-D_STDINT_H -Wno-address

# linker flags used to generate the main object file
LDFLAGS		= -nostdlib -Wl,--no-check-sections -u call_user_start \
		-Wl,-static

# linker script used for the above linkier step
LD_SCRIPT	= eagle.app.v6.ld

# various paths from the SDK used in this project
SDK_LIBDIR	= lib
SDK_LDDIR	= ld
SDK_INCDIR	= include include/json

# select which tools to use as compiler, librarian and linker
CC		:= $(XTENSA_TOOLS_ROOT)xtensa-lx106-elf-gcc
AR		:= $(XTENSA_TOOLS_ROOT)xtensa-lx106-elf-ar
LD		:= $(XTENSA_TOOLS_ROOT)xtensa-lx106-elf-gcc


####
#### no user configurable options below here
####
SRC_DIR		:= $(MODULES)
BUILD_DIR	:= $(addprefix $(BUILD_BASE)/,$(MODULES))

SDK_LIBDIR	:= $(addprefix $(SDK_BASE)/,$(SDK_LIBDIR))
SDK_INCDIR	:= $(addprefix -I$(SDK_BASE)/,$(SDK_INCDIR))

SRC		:= $(foreach sdir,$(SRC_DIR),$(wildcard $(sdir)/*.c))
OBJ		:= $(patsubst %.c,$(BUILD_BASE)/%.o,$(SRC))
LIBS		:= $(addprefix -l,$(LIBS))
APP_AR		:= $(addprefix $(BUILD_BASE)/,$(TARGET)_app.a)
TARGET_OUT	:= $(addprefix $(BUILD_BASE)/,$(TARGET).out)

LD_SCRIPT	:= $(addprefix -T$(SDK_BASE)/$(SDK_LDDIR)/,$(LD_SCRIPT))

INCDIR	:= $(addprefix -I,$(SRC_DIR))
EXTRA_INCDIR	:= $(addprefix -I,$(EXTRA_INCDIR))
MODULE_INCDIR	:= $(addsuffix /include,$(INCDIR))

INCLUDE         := $(INCDIR) $(MODULE_INCDIR) $(EXTRA_INCDIR) $(SDK_INCDIR)


V ?= $(VERBOSE)
ifeq ("$(V)","1")
Q :=
vecho := @true
else
Q := @
vecho := @echo
endif

vpath %.c $(SRC_DIR)

define compile-objects
$1/%.o: %.c
	$(vecho) "CC $$<"
	$(Q) mkdir -p $$(shell dirname $$@)
	$(Q) $(CC) $(INCLUDE) $(CFLAGS) -MMD -MF $$(@:.o=.d) -c $$< -o $$@
endef

.PHONY: all flash blankflash run clean

all: $(TARGET_OUT) $(FW_BASE)

$(TARGET_OUT): $(APP_AR)
	$(vecho) "LD $@"
	$(Q) $(LD) -L$(SDK_LIBDIR) $(LD_SCRIPT) $(LDFLAGS) -Wl,--start-group \
		$(LIBS) $(APP_AR) -Wl,--end-group -o $@

$(FW_BASE): $(TARGET_OUT)
	$(vecho) "FW $@"
	$(Q) mkdir -p $@
	$(Q) $(ESPTOOL) elf2image $(TARGET_OUT) --output $@/

$(APP_AR): $(OBJ)
	$(vecho) "AR $@"
	$(Q) $(AR) cru $@ $(OBJ)

$(BUILD_BASE)/.flash: $(TARGET_OUT) $(FW_BASE)
	$(Q) $(ESPTOOL) --port $(ESPPORT) --baud $(ESPBAUD) write_flash \
		0x00000 $(FW_BASE)/0x00000.bin 0x40000 $(FW_BASE)/0x40000.bin
	$(Q) touch $@

flash: $(BUILD_BASE)/.flash

blankflash:
	$(Q) $(ESPTOOL) --port $(ESPPORT) --baud $(ESPBAUD) write_flash \
		0x7E000 $(SDK_BASE)/bin/blank.bin

run: flash
	$(Q) $(ESPTOOL) --port $(ESPPORT) --baud 115200 run --terminal

clean:
	$(Q) rm -f $(APP_AR)
	$(Q) rm -f $(TARGET_OUT)
	$(Q) rm -rf $(BUILD_BASE)
	$(Q) rm -rf $(FW_BASE)

$(foreach bdir,$(BUILD_DIR),$(eval $(call compile-objects,$(bdir))))

-include $(filter %.d,$(OBJ:%.o=%.d))

