CC := g++
CFLAGS := -lssl -lcrypto -Wno-deprecated-declarations
BUILDDIR := bin
PUBLICDIR := public-keys
PRIVATEDIR := private-keys
LIB := -L lib
INC := -I include

keys: 
	mkdir -p $(PUBLICDIR)
	mkdir -p $(PRIVATEDIR)

$(BUILDDIR): keys
	mkdir -p bin 

install: 
	@echo "Installing OpenSSL Dependencies"
	apt-get install openssl
	apt-get install libssl-dev

all: $(BUILDDIR)
	# $(CC) lib/dh.cpp -o $(BUILDDIR)/dh $(CFLAGS) $(LIB) $(INC)
	$(CC) lib/aes.cpp lib/ecdh.cpp -o $(BUILDDIR)/ecdh $(CFLAGS) $(LIB) $(INC)

build: all
	$(CC) src/main.cpp -o $(BUILDDIR)/main $(CFLAGS) $(LIB) $(INC);

test: $(BUILDDIR)
	$(CC) $(CFLAGS) test/tester.cpp -o $(BUILDDIR)/tester
	$(BUILDDIR)/tester

clean: 
	@echo "Cleaning...";
	$(RM) -r $(BUILDDIR) 
	@echo "Removing extraneous .pem files"
	$(RM) -f *.pem 