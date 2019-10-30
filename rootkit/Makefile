TARGET = myrootkit
obj-m := ${TARGET}ko.o
${TARGET}ko-objs := ${TARGET}.o motekit/motekit.o





default:
	${MAKE} modules \
		--directory "/lib/modules/$(shell uname --release)/build" \
		M="$(shell pwd)"


clean:
	${MAKE} clean \
		--directory "/lib/modules/$(shell uname --release)/build" \
		M="$(shell pwd)"
