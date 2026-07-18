# RDBMS / SQL parser library build

CXX      := g++
FLEX     := flex
CXXFLAGS := -g
PERM     := -fpermissive

TARGET_LIBDBMS := libdbms.a

LEX_SRC := lex.yy.c
PARSER_L := Parser.l

LIBDBMS_OBJS := \
	../uapi/sql_api.o \
	../core/qep.o \
	../core/sql_name.o \
	lex.yy.o \
	SqlSelectParserCFG.o \
	SqlDeleteParserCFG.o \
	SqlUpdateParserCFG.o \
	SqlCreateParserCFG.o \
	SqlInsertIntoParserCFG.o \
	../BPlusTreeLib/BPlusTree.o \
	../core/BPlusTreeCompFn.o \
	../core/rdbms_ds.o \
	../core/ds_bplus_adapter.o \
	../core/ds_list_adapter.o \
	../core/sql_utils.o \
	../core/sql_create.o \
	../core/sql_select.o \
	../core/sql_where.o \
	../core/Catalog.o \
	../gluethread/glthread.o \
	../core/sql_insert_into.o \
	../core/sql_delete.o \
	../core/sql_update.o \
	../core/sql_join.o \
	../c-hashtable/hashtable.o \
	../c-hashtable/hashtable_itr.o \
	../core/sql_io.o \
	../core/SqlMexprIntf.o \
	../core/sql_group_by.o \
	../core/sql_order_by.o \
	SqlParserMain.o \
	SqlToMexprEnumMapper.o

.PHONY: all clean lib

all: $(TARGET_LIBDBMS)

lib: $(TARGET_LIBDBMS)

$(TARGET_LIBDBMS): $(LIBDBMS_OBJS)
	ar rcs $@ $^

$(LEX_SRC): $(PARSER_L)
	$(FLEX) $(PARSER_L)

lex.yy.o: $(LEX_SRC) ParserExport.h
	$(CXX) $(CXXFLAGS) -c $(LEX_SRC) -o $@

SqlParserMain.o: SqlParserMain.c
	$(CXX) $(CXXFLAGS) -c SqlParserMain.c -o $@

SqlSelectParserCFG.o: SqlSelectParserCFG.c ParserExport.h sql_parser_bind.h SqlEnums.h
	$(CXX) $(CXXFLAGS) -c SqlSelectParserCFG.c -o $@

SqlCreateParserCFG.o: SqlCreateParserCFG.c ParserExport.h sql_parser_bind.h SqlEnums.h
	$(CXX) $(CXXFLAGS) -c SqlCreateParserCFG.c -o $@

SqlInsertIntoParserCFG.o: SqlInsertIntoParserCFG.c ParserExport.h sql_parser_bind.h SqlEnums.h
	$(CXX) $(CXXFLAGS) -c SqlInsertIntoParserCFG.c -o $@

SqlDeleteParserCFG.o: SqlDeleteParserCFG.c ParserExport.h sql_parser_bind.h SqlEnums.h
	$(CXX) $(CXXFLAGS) -c SqlDeleteParserCFG.c -o $@

SqlUpdateParserCFG.o: SqlUpdateParserCFG.c ParserExport.h sql_parser_bind.h SqlEnums.h
	$(CXX) $(CXXFLAGS) -c SqlUpdateParserCFG.c -o $@

SqlToMexprEnumMapper.o: SqlToMexprEnumMapper.c SqlEnums.h
	$(CXX) $(CXXFLAGS) -c SqlToMexprEnumMapper.c -o $@

../core/qep.o: ../core/qep.c
	$(CXX) $(CXXFLAGS) -c ../core/qep.c -o $@

../core/sql_create.o: ../core/sql_create.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_create.c -o $@

../core/sql_update.o: ../core/sql_update.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_update.c -o $@

../core/sql_insert_into.o: ../core/sql_insert_into.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_insert_into.c -o $@

../core/sql_select.o: ../core/sql_select.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_select.c -o $@

../core/sql_utils.o: ../core/sql_utils.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_utils.c -o $@

../core/sql_io.o: ../core/sql_io.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_io.c -o $@

../core/sql_group_by.o: ../core/sql_group_by.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_group_by.c -o $@

../core/sql_order_by.o: ../core/sql_order_by.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_order_by.c -o $@

../core/sql_where.o: ../core/sql_where.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_where.c -o $@

../core/sql_join.o: ../core/sql_join.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_join.c -o $@

../core/sql_name.o: ../core/sql_name.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_name.c -o $@

../core/sql_delete.o: ../core/sql_delete.c
	$(CXX) $(CXXFLAGS) -c ../core/sql_delete.c -o $@

../BPlusTreeLib/BPlusTree.o: ../BPlusTreeLib/BPlusTree.c
	$(CXX) $(CXXFLAGS) -c $(PERM) ../BPlusTreeLib/BPlusTree.c -o $@

../core/BPlusTreeCompFn.o: ../core/BPlusTreeCompFn.c
	$(CXX) $(CXXFLAGS) -c $(PERM) ../core/BPlusTreeCompFn.c -o $@

../core/rdbms_ds.o: ../core/rdbms_ds.c
	$(CXX) $(CXXFLAGS) -c ../core/rdbms_ds.c -o $@

../core/ds_bplus_adapter.o: ../core/ds_bplus_adapter.c
	$(CXX) $(CXXFLAGS) -c $(PERM) ../core/ds_bplus_adapter.c -o $@

../core/ds_list_adapter.o: ../core/ds_list_adapter.c
	$(CXX) $(CXXFLAGS) -c ../core/ds_list_adapter.c -o $@

../core/Catalog.o: ../core/Catalog.c
	$(CXX) $(CXXFLAGS) -c ../core/Catalog.c -o $@

../gluethread/glthread.o: ../gluethread/glthread.c
	$(CXX) $(CXXFLAGS) -c ../gluethread/glthread.c -o $@

../c-hashtable/hashtable.o: ../c-hashtable/hashtable.c
	$(CXX) $(CXXFLAGS) -c ../c-hashtable/hashtable.c -o $@

../c-hashtable/hashtable_itr.o: ../c-hashtable/hashtable_itr.c
	$(CXX) $(CXXFLAGS) -c ../c-hashtable/hashtable_itr.c -o $@

../core/SqlMexprIntf.o: ../core/SqlMexprIntf.cpp
	$(CXX) $(CXXFLAGS) -c ../core/SqlMexprIntf.cpp -o $@

../uapi/sql_api.o: ../uapi/sql_api.cpp
	$(CXX) $(CXXFLAGS) -c ../uapi/sql_api.cpp -o $@

clean:
	rm -f $(TARGET_LIBDBMS)
	rm -f $(LEX_SRC)
	rm -f *.o
	rm -f ../core/*.o
	rm -f ../BPlusTreeLib/*.o
	rm -f ../uapi/*.o
