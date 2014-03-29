CURPWD = $(shell pwd)

THIRD_PARTY_HOME=/usr/local/third_party
NGX_ROOT=/home/im/cm/ngx
DEBUG=1

DEFINES += -DCC_KEYBOARD_SUPPORT

FILTE_FILES= ! -regex ".*/core/nginx\.c\|.*/ngx_modules\.c"	\
#	! -regex '.*/ngx_modules.c\|.*/proc/.*\|.*/core/nginx\.c\|.*/ngx_dso_module\.c'	\
#	! -regex '.*/core/ngx_cycle\.c\|.*/core/ngx_conf_file\.c\|.*/core/ngx_open_file_cache\.c\|.*/core/ngx_file\.c\|'
	

SOURCES =  $(shell find $(NGX_ROOT) $(FILTE_FILES) -regex '.*\.cpp\|.*\.c')	\
	$(shell find src -regex '.*\.cpp\|.*\.c')

ifdef s
TARGET=objs/s
SOURCES+= ./server.c
else
TARGET=objs/c
SOURCES+= ./client.c
endif

SHAREDLIBS = -Wl,-E -lpthread -ldl -lcrypt -lm  -lcrypto -lz
DEP_LIBS = $(THIRD_PARTY_HOME)/yajl/lib/libyajl.so

include $(NGX_ROOT)/ngx_test.mk


INCLUDES +=	-I objs \
	-I $(THIRD_PARTY_HOME)/yajl/include \
	-I $(THIRD_PARTY_HOME)/pcre/include \
	-I ngx \
	-I src


STATICLIBS += \
	$(THIRD_PARTY_HOME)/pcre/lib/libpcre.a	\
	$(THIRD_PARTY_HOME)/expat-2.1.0/lib/libexpat.a


####### Build rules
$(TARGET): $(OBJECTS) $(STATICLIBS) $(CORE_MAKEFILE_LIST)
	@mkdir -p $(@D)
	@echo "$(LOG_LINK)$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(SHAREDLIBS) $(STATICLIBS) $(LIBS)"
	$(LOG_LINK)$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(SHAREDLIBS) $(STATICLIBS) $(LIBS)

####### Compile
$(OBJ_DIR)/%.o: ../%.cpp $(CORE_MAKEFILE_LIST)
	@mkdir -p $(@D)
	@echo "1:$(OBJ_DIR)/%.o: ../%.cpp $(CORE_MAKEFILE_LIST)"
	@echo "1.1:$(LOG_CXX)$(CXX) $(CXXFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@"
	$(LOG_CXX)$(CXX) $(CXXFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OBJ_DIR)/%.o: %.cpp $(CORE_MAKEFILE_LIST)
	@mkdir -p $(@D)
	@echo "2:$(OBJ_DIR)/%.o: %.cpp $(CORE_MAKEFILE_LIST)"
	$(LOG_CXX)$(CXX) $(CXXFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OBJ_DIR)/%.o: %.c $(CORE_MAKEFILE_LIST)
	@mkdir -p $(@D)
	@echo "$(LOG_CC)$(CC) $(CCFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@"
	$(LOG_CC)$(CC) $(CCFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

s: 
	make s=1
