CC := g++
CFLAGS := 
BUILDDIR := bin
LIB := -L lib
INC := -I include

$(BUILDDIR): 
	mkdir bin 

test: $(BUILDDIR)
	@echo "$(CC) test/tester.cpp -o $(BUILDDIR)/tester"
	$(CC) test/tester.cpp -o $(BUILDDIR)/tester
	@echo "$(BUILDDIR)/tester"
	$(BUILDDIR)/tester

clean: 
	@echo " Cleaning..."; 
	@echo " $(RM) -r $(BUILDDIR) "; $(RM) -r $(BUILDDIR) 