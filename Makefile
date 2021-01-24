
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GNU GPL-v3
#

CC			:= cc
CXX			:= cxx
LD			:= $(CXX)
VG			:= valgrind

BASE_DIR	:= $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR	:= $(strip $(patsubst %/, %, $(BASE_DIR)))

DEP_DIR		:= $(BASE_DIR)/.deps
SRC_DIR		:= $(BASE_DIR)/src
INCLUDE_DIR	:=	-I$(SRC_DIR)/include				\
				-I$(SRC_DIR)/include/third_party

WARN_FLAGS	:= -Wall -Wextra -Wstrict-aliasing=3 -W
LIB_LDFLAGS	:= -lpthread

LD_FLAGS	:= -fPIE -fpie $(WARN_FLAGS)
CFLAGS		:= -fPIE -fpie -std=c11 $(INCLUDE_DIR) $(WARN_FLAGS)
CXXFLAGS	:= -fPIE -fpie -std=c++2a $(INCLUDE_DIR) $(WARN_FLAGS)
VGFLAGS		:= --leak-check=full --show-leak-kinds=all --track-origins=yes --track-fds=yes -s

TARGET_BIN	:= teavpn2
USE_CLIENT	:= 1
USE_SERVER	:= 1

ifndef DEFAULT_OPTIMIZATION
	DEFAULT_OPTIMIZATION = -O0
endif


## CCXXFLAGS is a group of flags that applies to CC and CXX.
ifeq ($(RELEASE_MODE),1)
	CCXXFLAGS	:=	-O3							\
					-DNDEBUG

	LDFLAGS		:=	$(LDFLAGS)					\
					-O3
else
	CCXXFLAGS	:=	$(DEFAULT_OPTIMIZATION)		\
					-ggdb3						\
					-grecord-gcc-switches		\
					-DTEAVPN_DEBUG

	LDFLAGS		:=	$(LDFLAGS)					\
					$(DEFAULT_OPTIMIZATION)
endif

CCXXFLAGS	:= $(CCXXFLAGS) -fstack-protector-strong -pedantic-errors

ifeq ($(OS),Windows_NT)
	CCXXFLAGS += -D WIN32
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		CCXXFLAGS += -D AMD64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			CCXXFLAGS += -D AMD64
		endif
		ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			CCXXFLAGS += -D IA32
		endif
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CCXXFLAGS += -D LINUX
	endif
	ifeq ($(UNAME_S),Darwin)
		CCXXFLAGS += -D OSX
	endif

	UNAME_P := $(shell uname -p)
	ifeq ($(UNAME_P),x86_64)
		CCXXFLAGS += -D AMD64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		CCXXFLAGS += -D IA32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		CCXXFLAGS += -D ARM
	endif
endif


MAIN_FILE		:= $(SRC_DIR)/sources/teavpn2/main.c
MAIN_OBJ		:= $(SRC_DIR)/sources/teavpn2/main.o
GLOBAL_SRC_DIR	:= $(SRC_DIR)/sources/teavpn2/global
CLIENT_SRC_DIR	:= $(SRC_DIR)/sources/teavpn2/client
SERVER_SRC_DIR	:= $(SRC_DIR)/sources/teavpn2/server

#
# Global module sources and objects.
# This module is required for server and client.
#
GLOBAL_SRC_CC		:= $(shell find "${GLOBAL_SRC_DIR}" -name '*.c')
GLOBAL_SRC_CXX		:= $(shell find "${GLOBAL_SRC_DIR}" -name '*.cpp')
GLOBAL_OBJ_CC		:= $(GLOBAL_SRC_CC:%=%.o)
GLOBAL_OBJ_CXX		:= $(GLOBAL_SRC_CXX:%=%.o)
GLOBAL_OBJ			:= $(strip $(GLOBAL_OBJ_CC) $(GLOBAL_OBJ_CXX))

# Global module dependencies.
GLOBAL_SRC_DIRL		:= $(shell find "${GLOBAL_SRC_DIR}" -type d)
GLOBAL_DEP_DIRS		:= $(GLOBAL_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
GLOBAL_DEP_FLAGS	 = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
GLOBAL_DEP_FILES	:= $(GLOBAL_SRC_CC) $(GLOBAL_SRC_CXX)
GLOBAL_DEP_FILES	:= $(GLOBAL_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)

#
# Client module sources and objects.
# This module is required for client.
#
ifeq ($(USE_CLIENT),1)
	CCXXFLAGS += -DUSE_TEAVPN_CLIENT=1
endif
CLIENT_SRC_CC		:= $(shell find "${CLIENT_SRC_DIR}" -name '*.c')
CLIENT_SRC_CXX		:= $(shell find "${CLIENT_SRC_DIR}" -name '*.cpp')
CLIENT_OBJ_CC		:= $(CLIENT_SRC_CC:%=%.o)
CLIENT_OBJ_CXX		:= $(CLIENT_SRC_CXX:%=%.o)
CLIENT_OBJ			:= $(strip $(CLIENT_OBJ_CC) $(CLIENT_OBJ_CXX))

# Client module dependencies.
CLIENT_SRC_DIRL		:= $(shell find "${CLIENT_SRC_DIR}" -type d)
CLIENT_DEP_DIRS		:= $(CLIENT_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
CLIENT_DEP_FLAGS	 = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
CLIENT_DEP_FILES	:= $(CLIENT_SRC_CC) $(CLIENT_SRC_CXX)
CLIENT_DEP_FILES	:= $(CLIENT_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)


#
# Server module sources and objects.
# This module is required for server.
#
ifeq ($(USE_SERVER),1)
	CCXXFLAGS += -DUSE_TEAVPN_SERVER=1
endif
SERVER_SRC_CC		:= $(shell find "${SERVER_SRC_DIR}" -name '*.c')
SERVER_SRC_CXX		:= $(shell find "${SERVER_SRC_DIR}" -name '*.cpp')
SERVER_OBJ_CC		:= $(SERVER_SRC_CC:%=%.o)
SERVER_OBJ_CXX		:= $(SERVER_SRC_CXX:%=%.o)
SERVER_OBJ			:= $(strip $(SERVER_OBJ_CC) $(SERVER_OBJ_CXX))

# Server module dependencies.
SERVER_SRC_DIRL		:= $(shell find "${SERVER_SRC_DIR}" -type d)
SERVER_DEP_DIRS		:= $(SERVER_SRC_DIRL:$(BASE_DIR)/%=$(DEP_DIR)/%)
SERVER_DEP_FLAGS	 = -MT $(@) -MMD -MP -MF $(DEP_DIR)/$(@:$(BASE_DIR)/%.o=%.d)
SERVER_DEP_FILES	:= $(SERVER_SRC_CC) $(SERVER_SRC_CXX)
SERVER_DEP_FILES	:= $(SERVER_DEP_FILES:$(BASE_DIR)/%=$(DEP_DIR)/%.d)

CFLAGS		:= $(strip $(CFLAGS) $(CCXXFLAGS))
CXXFLAGS	:= $(strip $(CXXFLAGS) $(CCXXFLAGS))

all: $(TARGET_BIN)

$(TARGET_BIN): $(GLOBAL_OBJ) $(SERVER_OBJ) $(CLIENT_OBJ) $(MAIN_OBJ)
	@echo " LD  " $(@)
	@$(LD) $(GLOBAL_OBJ) $(SERVER_OBJ) $(CLIENT_OBJ) $(MAIN_OBJ) -o $(@) $(LIB_LDFLAGS)

clean:


