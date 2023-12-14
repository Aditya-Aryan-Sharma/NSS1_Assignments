CXX = g++
CXXFLAGS = -std=c++11 -Wall

SRCS = getacl.cpp setacl.cpp fput.cpp header.cpp fget.cpp cd.cpp createdir.cpp precompute.cpp
OBJS = $(SRCS:.cpp=.o)

BINARIES = getacl setacl fput fget cd createdir precompute

all: $(BINARIES)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

getacl: getacl.o header.o
	$(CXX) $(CXXFLAGS) $^ -o $@
	chmod u+s $@

setacl: setacl.o header.o
	$(CXX) $(CXXFLAGS) $^ -o $@
	chmod u+s $@

fput: fput.o header.o
	$(CXX) $(CXXFLAGS) $^ -o $@
	chmod u+s $@

fget: fget.o header.o
	$(CXX) $(CXXFLAGS) $^ -o $@
	chmod u+s $@

cd: cd.o header.o
	$(CXX) $(CXXFLAGS) $^ -o $@
	chmod u+s $@

createdir: createdir.o header.o
	$(CXX) $(CXXFLAGS) $^ -o $@
	chmod u+s $@

precompute: precompute.o header.o
	$(CXX) $(CXXFLAGS) $^ -o $@

