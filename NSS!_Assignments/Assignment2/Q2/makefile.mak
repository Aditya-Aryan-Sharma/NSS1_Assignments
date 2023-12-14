CXX := g++
CXXFLAGS := -Wall -Wextra
LDFLAGS := -lssl -lcrypto

SRC_FILES := Q2_server.cpp Q2_client.cpp rsaderive.cpp passderive.cpp
EXE_FILES := $(SRC_FILES:.cpp=)

.PHONY: all clean $(EXE_FILES)

all: $(EXE_FILES)

$(EXE_FILES): %: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(EXE_FILES)

