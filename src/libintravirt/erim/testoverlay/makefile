CFLAGS+=-g -I. -I../ -I../../ -I../../sysdeps/generic/ -fno-inline

TESTCASES=test_application test_application_integrity

LIBRARIES=  -L../../ -lintravirt
LDLIBS= -lm $(LIBRARIES)

all: $(TESTCASES) run

%: %.c
	$(CC) $(CFLAGS) -o $@ $^ -L../../ -lintravirt

run: $(TESTCASES)
	for test in $(TESTCASES); do \
		{ LD_LIBRARY_PATH=../../ ./$$test; } > test.out 2>&1 ; \
		result=` tail -n 2 test.out | md5sum | cut -d ' ' -f 1`; \
		expected="bfe9e4f99493aca83844c79ed331b0f4"; \
		basename=`basename $$test`;\
		if [ $$result = $$expected ]; then \
			echo "[$$basename] Succesful";\
		else \
			echo "[$$basename] FAILED $$result";\
			cat test.out; \
			exit 1;\
		fi; \
		rm test.out; \
	done

clean:
	rm -f *.o
	rm -f $(TESTCASES)
