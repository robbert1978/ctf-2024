#!/bin/sh

./ugo
llvm-as hello.ll -o hello.bc
llc hello.bc -o hello.s
as -o hello.o hello.s
gcc -no-pie -static hello.o -o hello
rm hello.bc hello.s hello.o