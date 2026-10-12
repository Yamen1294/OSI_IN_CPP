CXX ?= g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra

osi: osi.cpp
	$(CXX) $(CXXFLAGS) osi.cpp -o osi

# Memory-safety build: AddressSanitizer + UBSan (also reports leaks at exit)
asan: osi.cpp
	$(CXX) -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer osi.cpp -o osi_asan

clean:
	rm -rf osi osi_asan received
