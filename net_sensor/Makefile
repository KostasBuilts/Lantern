CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
LDLIBS    = -lpcap -lyaml-cpp -lcrypto

SRCS = $(wildcard src/*.cpp)
OBJS = $(SRCS:src/%.cpp=build/%.o)

build/net_sensor: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

build/%.o: src/%.cpp $(wildcard src/*.h) | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: clean
