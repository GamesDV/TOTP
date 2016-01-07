# on Linux. Just run "make" to compile it.
#

GPP=g++
GCC=gcc
OUTFILE="TOTP.so"

COMPILE_FLAGS=-c -O3 -w -DLINUX -I lib/sdk/amx/



all:
	@echo Compiling plugin..
	$(GPP) $(COMPILE_FLAGS) *.cpp
	@echo Compiling plugin SDK..
	$(GPP) $(COMPILE_FLAGS) lib/sdk/*.cpp
	$(GCC) $(COMPILE_FLAGS) lib/sdk/amx/*.c
	
	$(GPP) -O2 -fshort-wchar -shared -o $(OUTFILE) *.o
	
	
	