
INSTDIR = /usr/local/pgsql/lib

PGSQL_SRC_PATH ?= /usr/local/src/postgresql-9.3.6
PGSQL_INCLUDE_PATH ?= $(PGSQL_SRC_PATH)/src/include
PGSQL_LIBRARY_PATH ?= $(PGSQL_SRC_PATH)/contrib/pgcrypto
export PGSQL_SRC_PATH
export PGSQL_INCLUDE_PATH
export PGSQL_LIBRARY_PATH

BINARY = data_encryption.so
OBJS = data_encryption.o

CC = /usr/bin/gcc
ifeq ($(debug),yes)
  CFLAGS = -c -Wall -O0 -ggdb $(DEBUG) -fPIC
else
  CFLAGS = -c -Wall -O3 -fPIC
endif

LFLAGS = -L$(PGSQL_LIBRARY_PATH)
LINKER = -lpgcrypto -Wl,-rpath,'$(PGSQL_LIBRARY_PATH)'
IFLAGS = -I$(PGSQL_INCLUDE_PATH) -I$(PGSQL_LIBRARY_PATH)

all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) -shared -o $(BINARY) $(OBJS) $(LFLAGS) $(LINKER)

%.o: %.c
	$(CC) $(CFLAGS) $(IFLAGS) $<

install: $(BINARY)
	@if [ -d $(INSTDIR) ];	\
	then	\
		cp $(BINARY) $(INSTDIR)/ &&	\
		chmod a+x $(INSTDIR)/$(BIN) &&	\
		echo "";	\
		echo "[SUCCESS] $(BINARY) Installed Complete in '$(INSTDIR)'.";	\
		echo "";	\
	else	\
		echo "[ERROR] $(BINARY) Installed Failure.($(INSTDIR) does't exist)";	\
	fi

uninstall:
	rm -f $(INSTDIR)/$(BIN)

clean: 
	rm -f $(BINARY) $(OBJS)
