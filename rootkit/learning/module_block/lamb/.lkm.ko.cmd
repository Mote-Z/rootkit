cmd_/root/module_block/lamb/lkm.ko := ld -r -m elf_x86_64 -T ./scripts/module-common.lds --build-id  -o /root/module_block/lamb/lkm.ko /root/module_block/lamb/lkm.o /root/module_block/lamb/lkm.mod.o
