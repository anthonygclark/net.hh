all:
	clang++ $(CFLAGS) --std=c++14 test.cc -Wall -Wextra -ggdb3 $(CPPFLAGS) -lpthread -o test
	clang++ $(CFLAGS) --std=c++14 test2.cc -Wall -Wextra -ggdb3 $(CPPFLAGS) -lpthread -o test2
	clang++ $(CFLAGS) --std=c++14 test3.cc -Wall -Wextra -ggdb3 $(CPPFLAGS) -lpthread -o test3

check:
	cppcheck --enable=all --std=c++11 *.cc *.hh

clean:
	$(RM) test test2 test3
