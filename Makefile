# =========================
# COMPILER
# =========================
CXX      := g++
CC       := gcc

# =========================
# BORINGSSL
# =========================
BORINGSSL_ROOT := /usr/local/include/quiche-boringssl
BORINGSSL_INC  := $(BORINGSSL_ROOT)/boringssl/src/include
BORINGSSL_LIBS := $(BORINGSSL_ROOT)/build/libssl.a $(BORINGSSL_ROOT)/build/libcrypto.a

# =========================
# FLAGS
# =========================
CXXFLAGS := -std=c++20 -O0 -g3 -g -Wall -Wextra -I$(BORINGSSL_INC) -Iinclude -I/usr/include/cassandra
CFLAGS   := -Wall -Wextra -I$(BORINGSSL_INC) -Iinclude
LDFLAGS  := -lxxhash -lcassandra -lDotenv -luring -loqs -lhiredis -lz -lmaxminddb -lquiche $(BORINGSSL_LIBS)

# =========================
# DIRECTORIES
# =========================
SRC_DIR  := src
INC_DIR  := include
BUILD    := build
TARGET   := Gate

# =========================
# FIND ALL SOURCES (RECURSIVE)
# =========================
CPP_SRCS := $(shell find $(SRC_DIR) -type f -name '*.cpp')
C_SRCS   := $(shell find $(SRC_DIR) -type f -name '*.c')

OBJS := $(CPP_SRCS:$(SRC_DIR)/%.cpp=$(BUILD)/%.o) \
$(C_SRCS:$(SRC_DIR)/%.c=$(BUILD)/%.o)

# =========================
# DEFAULT RULE
# =========================
all: $(TARGET)

# =========================
# LINK
# =========================
$(TARGET): $(OBJS)
	@echo "Linking $@"
	@$(CXX) $^ -o $@ $(LDFLAGS)

# =========================
# C++ COMPILE
# =========================
$(BUILD)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "CXX $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# =========================
# C COMPILE
# =========================
$(BUILD)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "CC  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# =========================
# CLEAN
# =========================
clean:
	@echo "Cleaning"
	@rm -rf $(BUILD) $(TARGET)

# =========================
# PHONY
# =========================
.PHONY: all clean