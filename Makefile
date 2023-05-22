CC := gcc
CFLAGS := 
LIB := -L lib
INC := -I include

test:
	$(CC) $(CFLAGS) test/tester.cpp $(INC) $(LIB) -o bin/tester