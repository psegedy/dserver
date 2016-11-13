CXX=g++
CXXFLAGS=-g -pedantic -Wall -Wextra -std=c++11
SOURCES=dserver.cpp dserver.hpp
EXECUTABLE=dserver

all:$(EXECUTABLE)

dserver: $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $@

clean:
	rm dserver