CURPWD = $(shell pwd)

THIRD_PARTY_HOME=/usr/local/third_party
NGX_ROOT=$(CURPWD)/ngx
DEBUG=1
TARGET=objs/nginx

DEFINES += -DCC_KEYBOARD_SUPPORT

SOURCES =  $(shell find ngx -regex '.*\.cpp\|.*\.c')	\
	$(shell find src -regex '.*\.cpp\|.*\.c')

SHAREDLIBS = -Wl,-E -lpthread -ldl -lcrypt -lm  -lcrypto -lz
DEP_LIBS = $(THIRD_PARTY_HOME)/yajl/lib/libyajl.so

include $(NGX_ROOT)/nginx.mk


INCLUDES +=	-I objs \
	-I $(THIRD_PARTY_HOME)/yajl/include \
	-I $(THIRD_PARTY_HOME)/pcre/include \
	-I src/xmpp/modules \
        -I src/xmpp \
	-I src/xmpp/parsers \
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
