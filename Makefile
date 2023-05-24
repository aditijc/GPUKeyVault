CC := g++
CFLAGS := -lssl -lcrypto -Wno-deprecated-declarations
BUILDDIR := bin
LIB := -L lib
INC := -I include

$(BUILDDIR): 
	mkdir bin 

install: 
	@echo "Installing OpenSSL Dependencies"
	apt-get install openssl
	apt-get install libssl-dev

all: $(BUILDDIR)
	$(CC) lib/dh.cpp -o $(BUILDDIR)/dh $(CFLAGS) $(LIB) $(INC)

test: $(BUILDDIR)
	$(CC) $(CFLAGS) test/tester.cpp -o $(BUILDDIR)/tester
	$(BUILDDIR)/tester

clean: 
	@echo "Cleaning...";
	$(RM) -r $(BUILDDIR) 