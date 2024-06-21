c_executables   = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

all: $(c_executables) $(cxx_executables)

$(c_executables): %: %.c
	gcc -g -o $@ $< -lpthread

$(cxx_executables): %: %.cpp
	g++ -g -o $@ $< -lpthread

clean:
	$(RM) $(c_executables) $(cxx_executables)
test: 

