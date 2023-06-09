#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
시스템콜이 필요한 다른 모든 작업을 수행하는 코드를 추가해줘야 한다.
pintos --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg' 을 통해 테스트 해볼 수 있음
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
    lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
    // TODO: user stack에 존재하는 stack frame의 인자들을 kernel에 복사
    //! syscall return값은 intr_frame의 rax에 저장
    // check_address(f->rsp);

    switch (f->R.rax)
    {
    case SYS_HALT:
        f->R.rax = halt();
        break;
    case SYS_EXIT:
        exit(0);
        break;
    case SYS_FORK:
        fork(f->R.rdi, f);
        break;
    case SYS_EXEC:
        f->R.rax = exec(f->R.rdi); 
        break;
    case SYS_WAIT:
        break;
    case SYS_CREATE:
        break;
    case SYS_REMOVE:
        break;
    case SYS_OPEN:
        break;
    case SYS_FILESIZE:
        break;
    case SYS_READ:
        break;
    case SYS_WRITE:
        break;
    case SYS_SEEK:
        break;
    case SYS_TELL:
        break;
    case SYS_CLOSE:
        break;
    
    default:
        break;
    }
	// printf ("system call!\n");
	// thread_exit ();
}

void check_address (void *addr) {
    if (is_kernel_vaddr(addr) || addr == NULL) {
        exit(-1);
    }
}

void get_argument(void *rsp, int *arg, int count) {
    check_address(&rsp);
    // 시스템 콜 인자를 커널에 복사
    // TODO: rsp에 count(argc)만큼의 데이터를 arg에 저장
    // TODO: 스택 포인터를 참조하여 count만큼 스택에 저장된 인자들을 arg배열로 복사
    rsp = rsp + 8; // return 값 빼기위해 +8
    for (int i = 0; i < count; i++) {
        arg[i] = rsp;
        rsp += 8; // pointer 는 8바이트이니까 +8
    }
}

uint64_t halt (void) {
    return power_off();
}

bool create (const char *file, unsigned initial_size) {
    
}

void exit(int status) {
    struct thread *curr = thread_current();
    // curr->exit_status = status;
    // printf("%s: exit(%d)", curr->name, status);
    // process_exit()이 thread_exit()통해 불려짐
    thread_exit();
}

int exec(const char *cmd_line) {
    // process_create_initd와 비슷하지만, thread_create은 fork에서 진행할 예정
    check_address(cmd_line);
    struct thread *curr = thread_current();

    // sema_init(&curr->exec_sema, 0);
    // sema_down(&curr->exec_sema);

    char *cmd_line_copy = palloc_get_page(0);
    if (!cmd_line_copy)
        exit(-1);

    strlcpy(cmd_line_copy, &cmd_line, PGSIZE);
    

    if (process_exec(cmd_line_copy) == -1)
        exit(-1);

    // sema_up(&curr->exec_sema);

    return thread_current()->tid;
}

void fork(const char *name, struct intr_frame *if_ ) {
    process_fork(name, if_);
}

bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);