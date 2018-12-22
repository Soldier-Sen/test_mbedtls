LOCAL_PATH	:= $(shell pwd)

LOCAL_TARGET	:= test_mbedtls
#COMPILER_PREFIX = arm-goke-linux-uclibcgnueabi-
CC	= $(COMPILER_PREFIX)gcc
CXX	= $(COMPILER_PREFIX)g++
AR	= $(COMPILER_PREFIX)ar

LOCAL_SRC	:= $(LOCAL_PATH)/test_mbedtls.c

LOCAL_INC	+= -I$(LOCAL_PATH)
LOCAL_INC	+= -I$(LOCAL_PATH)/intstall.x64/include 
#LOCAL_INC	+= -I$(LOCAL_PATH)

LOCAL_CFLAGS	+= -std=gnu99 -Os 
LOCAL_LDFLAGS	+= -L$(LOCAL_PATH)/intstall.x64/lib -lmbedtls -lmbedcrypto -lmbedx509

LOCAL_LDFLAGS	+= -lpthread 

SRC_OBJS	:= $(LOCAL_SRC:.c=.o)

$(LOCAL_TARGET):$(SRC_OBJS)
	@$(CC) -o $@ $(SRC_OBJS) $(LOCAL_LDFLAGS)
	@rm -f $(SRC_OBJS)

%.o:%.c
	@$(CC) $(LOCAL_INC) $(LOCAL_CFLAGS) -o $@ -c $<
	
clean:
	@rm -f $(LOCAL_TARGET) $(SRC_OBJS)

.PHONY:$(LOCAL_TARGET)
.PHONY:clean

