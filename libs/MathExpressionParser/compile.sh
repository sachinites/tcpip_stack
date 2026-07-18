#!/bin/bash
# Regenerate the reentrant flex scanner. The generated lex.yy.c holds the
# per-instance parser helpers and the flex scanner; it is compiled by the
# consuming application (and by the multi-threaded smoke test below), not
# archived into libMexpr.a, so that integrators can supply their own Parser.l.
flex Parser.l

rm -f  libMexpr.a
rm -f *.o
g++ -g -c -fpermissive ExpressionParser.c -o ExpressionParser.o
g++ -g -c Operators.cpp -o Operators.o
g++ -g -c Dtype.cpp -o Dtype.o
g++ -g -c MexprTree.cpp -o MexprTree.o
g++ -g -c EnumConvertor.cpp -o EnumConvertor.o
g++ -g -c Aggregators.cpp -o Aggregators.o
ar rcs libMexpr.a ExpressionParser.o Operators.o Dtype.o MexprTree.o Aggregators.o EnumConvertor.o
g++ -g -c mt_thread_test.cpp -o mt_thread_test.o
g++ -g -fpermissive lex.yy.c ExpressionParser.o mt_thread_test.o -o mt_test -lpthread