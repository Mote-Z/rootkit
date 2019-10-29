TARGET = myrootkit
obj-m := ${TARGET}ko.o
${TARGET}ko-objs := ${TARGET}.o module_handler/module_handler.o zeroevil/zeroevil.o





default:
	${MAKE} modules \
		--directory "/lib/modules/$(shell uname --release)/build" \
		M="$(shell pwd)"


clean:
	${MAKE} clean \
		--directory "/lib/modules/$(shell uname --release)/build" \
		M="$(shell pwd)"
