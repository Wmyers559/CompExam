# Makefile for the GIFT cryptosystem
# Made more modular by
# 	Riley Myers
# 	wmyers@nmt.edu/william.myers@inl.gov

CC 			:= clang
CFLAGS		:= -Wall -Wpedantic -std=c99 -g

.PHONY: all intel clean verify

all: verify

bin/%.o: %.c
	@mkdir -p bin
	$(CC) $(CFLAGS) $^ -c -o $@

bin/test: bin/crypto.o bin/test.o
	$(CC) $(CFLAGS) $^ -o $@

verify: bin/test
	@echo "Running verification tests"
	@bin/test

clean:
	rm -f bin/*
