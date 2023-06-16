CXX := nvcc
CXXLIBS := lib/interface.cpp lib/ecdh.cpp lib/aes.cpp lib/rsa.cpp lib/cursa.cu
CXXFLAGS := -lssl -lcrypto -Wno-deprecated-declarations -arch=sm_52
BUILDDIR := bin
RESULTSDIR := results
PUBLICDIR := public-keys
PRIVATEDIR := private-keys
LIB := -L lib
INC := -I include

.DEFAULT_GOAL := build

keys: 
	mkdir -p $(PUBLICDIR)
	mkdir -p $(PRIVATEDIR)

$(BUILDDIR): keys
	mkdir -p $(BUILDDIR)

install: 
	@echo "Installing OpenSSL Dependencies"
	apt-get install openssl
	apt-get install libssl-dev

build: $(BUILDDIR)
	$(CXX) $(CXXLIBS) src/main.cpp -o $(BUILDDIR)/main $(CXXFLAGS) $(LIB) $(INC);

test: $(BUILDDIR)
	$(CXX) $(CXXLIBS) test/tester.cpp -o $(BUILDDIR)/tester $(CXXFLAGS) $(LIB) $(INC);
	$(BUILDDIR)/tester

time: $(BUILDDIR)
	mkdir -p $(RESULTSDIR)
	$(CXX) $(CXXLIBS) test/timer.cpp -o $(BUILDDIR)/timer $(CXXFLAGS) $(LIB) $(INC);
	$(BUILDDIR)/timer

clean: 
	@echo "Cleaning...";
	$(RM) -r $(BUILDDIR)
	$(RM) -r $(RESULTSDIR)
	@echo "Removing extraneous .pem files"
	$(RM) -f *.pem 