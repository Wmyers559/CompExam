# Makefile for the GIFT cryptosystem
# Made more modular by
# 	Riley Myers
# 	wmyers@nmt.edu/william.myers@inl.gov

CC 			:= clang
AVR-CC 		:= avr-gcc
ARM-CC		:= arm-none-eabi-gcc

CFLAGS		:= -Wall -Wpedantic -std=c99 -g
AVR-FLAGS 	:= -mmcu=atxmega128d3
ARM-FLAGS 	:=


.PHONY: all intel arm avr clean 

all: intel intel2

bin/%.o: %.c
	@mkdir -p bin
	$(CC) $(CFLAGS) $^ -c -o $@

intel: bin/gift.o bin/verbose.o bin/comline.o bin/crypto.o
	$(CC) $(CFLAGS) $^ -o bin/gift
intel2: bin/giftCycle.o bin/verbose.o bin/comline.o bin/crypto.o
	$(CC) $(CFLAGS) $^ -o bin/giftCycle

##### Don't run these yet, they aren't finished #####
arm: bin/gift.o bin/verbose.o bin/comline.o bin/crypto.o
	$(ARM-CC) $(CFLAGS) $^ -o bin/gift-$@

avr: bin/gift.o bin/verbose.o bin/comline.o bin/crypto.o
	$(AVR-CC) $(CFLAGS) $^ -o bin/gift-$@
#####################################################


clean:
	rm -f bin/*
