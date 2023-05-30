CXX := g++
CXXLIBS := lib/interface.cpp lib/ecdh.cpp lib/aes.cpp lib/rsa.cpp 
CFLAGS := -lssl -lcrypto -Wno-deprecated-declarations -Wno-free-nonheap-object
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

build: $(BUILDDIR)
	$(CXX) $(CXXLIBS) src/main.cpp -o $(BUILDDIR)/main $(CFLAGS) $(LIB) $(INC);

test: $(BUILDDIR)
	$(CXX) $(CXXLIBS) test/tester.cpp -o $(BUILDDIR)/tester $(CFLAGS) $(LIB) $(INC);
	$(BUILDDIR)/tester

clean: 
	@echo "Cleaning...";
	$(RM) -r $(BUILDDIR)
	@echo "Removing extraneous .pem files"
	$(RM) -f *.pem 