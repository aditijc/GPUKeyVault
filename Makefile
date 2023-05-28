CXX := g++
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

# all: $(BUILDDIR)
# 	$(CXX) lib/aes.cpp lib/ecdh.cpp -o $(BUILDDIR)/ecdh $(CFLAGS) $(LIB) $(INC)

build: $(BUILDDIR)
	$(CXX) lib/interface.cpp lib/ecdh.cpp lib/aes.cpp src/main.cpp -o $(BUILDDIR)/main $(CFLAGS) $(LIB) $(INC);

test: $(BUILDDIR)
	$(CXX) lib/interface.cpp lib/ecdh.cpp lib/aes.cpp test/tester.cpp -o $(BUILDDIR)/tester $(CFLAGS) $(LIB) $(INC);
	$(BUILDDIR)/tester

clean: 
	@echo "Cleaning...";
	$(RM) -r $(BUILDDIR)
	@echo "Removing extraneous .pem files"
	$(RM) -f *.pem 