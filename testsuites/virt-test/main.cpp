#include <assert.h>
#include <hel-syscalls.h>
#include <hel.h>
#include <iostream>

int main() {
	HelHandle vspace, vcpu, mem;
	HEL_CHECK(helCreateVirtualizedSpace(&vspace));

	HEL_CHECK(helAllocateMemory(0x10000, 0, nullptr, &mem));

	void *fake_ptr;
	HEL_CHECK(helMapMemory(
		mem,
		vspace,
		0x0,
		0x0,
		0x10000,
		kHelMapFixed | kHelMapProtRead | kHelMapProtWrite | kHelMapProtExecute,
		&fake_ptr
	));
	assert(fake_ptr == nullptr);

	void *actual_ptr;
	HEL_CHECK(helMapMemory(
		mem,
		kHelNullHandle,
		nullptr,
		0,
		0x10000,
		kHelMapProtRead | kHelMapProtWrite,
		&actual_ptr
	));

	uint8_t code[] = {0xF4};
	memcpy((uint8_t *) actual_ptr + 0x7C00, code, sizeof(code));

	HEL_CHECK(helCreateVirtualizedCpu(vspace, &vcpu));

	HelX86VirtualizationRegs regs {};
	HEL_CHECK(helLoadRegisters(vcpu, kHelRegsVirtualization, (void *) &regs));

	regs.rip = 0x7C00;
	regs.rflags = (1 << 1);
	regs.cs = {.base = 0, .limit = 0xFFFF, .selector = 0, .type = 3, .present = 1, .s = 1};

	HelX86SegmentRegister seg {};
	seg.limit = 0xFFFF;
	seg.type = 3;
	seg.s = 1;
	seg.present = 1;
	regs.ds = seg;
	regs.es = seg;
	regs.fs = seg;
	regs.gs = seg;
	regs.ss = seg;

	regs.ldt.type = 2;
	regs.ldt.present = 1;
	regs.ldt.limit = 0xFFFF;

	regs.tr.limit = 0xFFFF;
	regs.tr.type = 3;
	regs.tr.present = 1;

	regs.gdt.limit = 0xFFFF;
	regs.idt.limit = 0xFFFF;

	HEL_CHECK(helStoreRegisters(vcpu, kHelRegsVirtualization, &regs));

	HelVmexitReason reason;
	HEL_CHECK(helRunVirtualizedCpu(vcpu, &reason));
	if(reason.exitReason == kHelVmexitHlt) {
		std::cout << "HLT Instruction" << std::endl;
	} else if(reason.exitReason == kHelVmexitError) {
		std::cout << "VMExit error" << std::endl;
	} else if(reason.exitReason == kHelVmexitUnknownPlatformSpecificExitCode) {
		std::cout << "Unknown platform specific exit code: 0x" << std::hex << reason.code
			  << std::dec << std::endl;
	} else if(reason.exitReason == kHelVmexitTranslationFault) {
		std::cout << "Translation fault: 0x" << std::hex << reason.address << std::dec
			  << std::endl;
	} else {
		std::cout << "Unknown reason: " << reason.exitReason << std::endl;
	}

	helCloseDescriptor(kHelThisUniverse, vcpu);
	helCloseDescriptor(kHelThisUniverse, vspace);
	helCloseDescriptor(kHelThisUniverse, mem);

	return 0;
}
