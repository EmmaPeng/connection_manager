all: $(TARGET)

CC = gcc
CXX = g++
CCFLAGS += -fPIC -pipe -W -Wall -Wpointer-arith -Wno-unused-parameter -DNDK_SET_VAR -Wno-unused-function -Wno-missing-field-initializers -D_POSIX_C_SOURCE=200112L --std=c99 -DNDK_SET_VAR
CXXFLAGS += -MMD -Wall -Werror -fPIC
ARFLAGS = cr

DEFINES += -DLINUX

THIS_MAKEFILE := $(CURDIR)/$(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))
ifndef NGX_ROOT
NGX_ROOT ?= $(realpath $(dir $(THIS_MAKEFILE))/)
else
RPATH_REL = ./ 
endif
NGX_SRC = $(NGX_ROOT)
OBJ_DIR ?= objs

LIB_DIR = $(NGX_SRC)/lib/
BIN_DIR = bin

INCLUDES += -I ngx \
	-I ngx/core \
	-I ngx/event \
	-I ngx/event/modules \
	-I ngx/os/unix \
	-I ngx/proc \
	-I ngx/http \
	-I ngx/tcp \
	-I ngx/mail

LBITS := $(shell getconf LONG_BIT)
ifeq ($(LBITS),64)
@echo “OS: x86_64”;
else
@echo “OS: 32bit”;
endif

ifeq ($(DEBUG), 1)
CCFLAGS += -g3 -O0
CXXFLAGS += -g3 -O0
DEFINES += -DDEBUG=1 -DNGX_HAVE_VARIADIC_MACROS=1
OBJ_DIR := $(OBJ_DIR)/debug
LIB_DIR := $(LIB_DIR)/debug
BIN_DIR := $(BIN_DIR)/debug
else
CCFLAGS += -O3
CXXFLAGS += -O3
DEFINES += -DNDEBUG
OBJ_DIR := $(OBJ_DIR)/release
LIB_DIR := $(LIB_DIR)/release
BIN_DIR := $(BIN_DIR)/release
endif

ifndef V
LOG_CC = @echo " CC $@";
LOG_CXX = @echo " CXX $@";
LOG_AR = @echo " AR $@";
LOG_LINK = @echo " LINK $@";
endif

OBJECTS := $(SOURCES:.cpp=.o)
$(warning  $(SOURCES))
OBJECTS := $(OBJECTS:.c=.o)
OBJECTS := $(subst ./,,$(OBJECTS))
OBJECTS := $(subst $(NGX_ROOT)/,,$(OBJECTS))
OBJECTS := $(addprefix $(OBJ_DIR)/, $(OBJECTS))
DEPS = $(OBJECTS:.o=.d)
CORE_MAKEFILE_LIST := $(MAKEFILE_LIST)
-include $(DEPS)


#SHAREDLIBS += -lglfw -lGLEW -lfontconfig
#SHAREDLIBS += -L$(FMOD_LIBDIR) -Wl,-rpath,$(RPATH_REL)/$(FMOD_LIBDIR)
#SHAREDLIBS += -L$(LIB_DIR) -Wl,-rpath,$(RPATH_REL)/$(LIB_DIR)
#LIBS = -lrt -lz

clean:	
	rm -rf objs *.out cscope.files GRTAGS GTAGS GPATH 

.PHONY: all clean

