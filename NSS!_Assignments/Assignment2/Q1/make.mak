CXX := g++
CXXFLAGS := -Wall -Wextra
LDFLAGS := -lssl -lcrypto

SRC_FILES := Q1_client.cpp Q1_server.cpp keyGenerate.cpp
EXE_FILES := $(SRC_FILES:.cpp=)

.PHONY: all clean $(EXE_FILES)

all: $(EXE_FILES)

$(EXE_FILES): %: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(EXE_FILES)
