CC := gcc
CFLAGS := 
BUILDDIR := bin
LIB := -L lib
INC := -I include

$(BUILDDIR): 
	mkdir bin 

test: $(BUILDDIR)
	@echo "$(CC) test/tester.c -o $(BUILDDIR)/tester"
	$(CC) test/tester.c -o $(BUILDDIR)/tester
	@echo "$(BUILDDIR)/tester"
	$(BUILDDIR)/tester

clean: 
	@echo " Cleaning..."; 
	@echo " $(RM) -r $(BUILDDIR) "; $(RM) -r $(BUILDDIR) 