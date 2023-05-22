CC := g++
CFLAGS := -lssl -lcrypto -lgmp -lgmpxx
BUILDDIR := bin
LIB := -L lib
INC := -I include

$(BUILDDIR): 
	mkdir bin 

install: 
	@echo "Installing OpenSSL Dependencies"
	apt-get install openssl
	apt-get install libssl-dev
	@echo "Installing DSA Dependencies for large integers"
	apt-get install libgmp-dev

all: 
	$(CC) lib/dsa.cpp -o $(BUILDDIR)/dsa $(CFLAGS)

test: $(BUILDDIR)
	@echo "$(CC) $(CFLAGS) test/tester.cpp -o $(BUILDDIR)/tester"
	$(CC) $(CFLAGS) test/tester.cpp -o $(BUILDDIR)/tester
	@echo "$(BUILDDIR)/tester"
	$(BUILDDIR)/tester

clean: 
	@echo " Cleaning..."; 
	@echo " $(RM) -r $(BUILDDIR) "; $(RM) -r $(BUILDDIR) 