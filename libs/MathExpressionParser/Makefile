# MathExpressionParser library build (mirrors compile.sh)

CXX      := g++
FLEX     := flex
CXXFLAGS := -g -fpermissive
LDFLAGS  := -lpthread

MEXPR_LIB     := libMexpr.a
MT_TEST       := mt_test
LEX_SRC       := lex.yy.c
PARSER_L      := Parser.l

MEXPR_LIB_OBJS := \
	ExpressionParser.o \
	Operators.o \
	Dtype.o \
	MexprTree.o \
	Aggregators.o \
	EnumConvertor.o

.PHONY: all clean lib test

all: $(MEXPR_LIB) $(MT_TEST)

lib: $(MEXPR_LIB)

test: $(MT_TEST)

$(MEXPR_LIB): $(MEXPR_LIB_OBJS)
	ar rcs $@ $^

$(MT_TEST): $(LEX_SRC) ExpressionParser.o mt_thread_test.o
	$(CXX) $(CXXFLAGS) $(LEX_SRC) ExpressionParser.o mt_thread_test.o -o $@ $(LDFLAGS)

$(LEX_SRC): $(PARSER_L)
	$(FLEX) $(PARSER_L)

ExpressionParser.o: ExpressionParser.c ParserExport.h MExprcppEnums.h
	$(CXX) $(CXXFLAGS) -c ExpressionParser.c -o $@

Operators.o: Operators.cpp Operators.h
	$(CXX) $(CXXFLAGS) -c Operators.cpp -o $@

Dtype.o: Dtype.cpp Dtype.h
	$(CXX) $(CXXFLAGS) -c Dtype.cpp -o $@

MexprTree.o: MexprTree.cpp MexprTree.h
	$(CXX) $(CXXFLAGS) -c MexprTree.cpp -o $@

Aggregators.o: Aggregators.cpp Aggregators.h
	$(CXX) $(CXXFLAGS) -c Aggregators.cpp -o $@

EnumConvertor.o: EnumConvertor.cpp ParserExport.h MExprcppEnums.h Dtype.h
	$(CXX) $(CXXFLAGS) -c EnumConvertor.cpp -o $@

mt_thread_test.o: mt_thread_test.cpp ParserExport.h
	$(CXX) $(CXXFLAGS) -c mt_thread_test.cpp -o $@

clean:
	rm -f $(MEXPR_LIB) $(MT_TEST) $(LEX_SRC)
	rm -f $(MEXPR_LIB_OBJS) mt_thread_test.o
