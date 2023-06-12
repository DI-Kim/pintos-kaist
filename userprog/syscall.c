// pass tests/userprog/args-none
// pass tests/userprog/args-single
// pass tests/userprog/args-multiple
// pass tests/userprog/args-many
// pass tests/userprog/args-dbl-space
// pass tests/userprog/halt
// pass tests/userprog/exit
// pass tests/userprog/create-normal
// pass tests/userprog/create-empty
// pass tests/userprog/create-null
// pass tests/userprog/create-bad-ptr
// pass tests/userprog/create-long
// pass tests/userprog/create-exists
// pass tests/userprog/create-bound
// pass tests/userprog/open-normal
// pass tests/userprog/open-missing
// pass tests/userprog/open-boundary
// pass tests/userprog/open-empty
// pass tests/userprog/open-null
// pass tests/userprog/open-bad-ptr
// pass tests/userprog/open-twice
// FAIL tests/userprog/close-normal
// FAIL tests/userprog/close-twice
// pass tests/userprog/close-bad-fd
// FAIL tests/userprog/read-normal
// pass tests/userprog/read-bad-ptr
// FAIL tests/userprog/read-boundary
// pass tests/userprog/read-zero
// pass tests/userprog/read-stdout
// pass tests/userprog/read-bad-fd
// pass tests/userprog/write-normal
// pass tests/userprog/write-bad-ptr
// pass tests/userprog/write-boundary
// pass tests/userprog/write-zero
// pass tests/userprog/write-stdin
// pass tests/userprog/write-bad-fd
// FAIL tests/userprog/fork-once
// FAIL tests/userprog/fork-multiple
// FAIL tests/userprog/fork-recursive
// FAIL tests/userprog/fork-read
// FAIL tests/userprog/fork-close
// FAIL tests/userprog/fork-boundary
// FAIL tests/userprog/exec-once
// FAIL tests/userprog/exec-arg
// FAIL tests/userprog/exec-boundary
// FAIL tests/userprog/exec-missing
// pass tests/userprog/exec-bad-ptr
// FAIL tests/userprog/exec-read
// FAIL tests/userprog/wait-simple
// FAIL tests/userprog/wait-twice
// FAIL tests/userprog/wait-killed
// pass tests/userprog/wait-bad-pid
// FAIL tests/userprog/multi-recurse
// FAIL tests/userprog/multi-child-fd
// FAIL tests/userprog/rox-simple
// FAIL tests/userprog/rox-child
// FAIL tests/userprog/rox-multichild
// FAIL tests/userprog/bad-read
// FAIL tests/userprog/bad-write
// FAIL tests/userprog/bad-read2
// FAIL tests/userprog/bad-write2
// FAIL tests/userprog/bad-jump
// FAIL tests/userprog/bad-jump2
// FAIL tests/filesys/base/lg-create
// FAIL tests/filesys/base/lg-full
// FAIL tests/filesys/base/lg-random
// FAIL tests/filesys/base/lg-seq-block
// FAIL tests/filesys/base/lg-seq-random
// FAIL tests/filesys/base/sm-create
// FAIL tests/filesys/base/sm-full
// FAIL tests/filesys/base/sm-random
// FAIL tests/filesys/base/sm-seq-block
// FAIL tests/filesys/base/sm-seq-random
// FAIL tests/filesys/base/syn-read
// FAIL tests/filesys/base/syn-remove
// FAIL tests/filesys/base/syn-write
// FAIL tests/userprog/no-vm/multi-oom
// pass tests/threads/alarm-single
// pass tests/threads/alarm-multiple
// pass tests/threads/alarm-simultaneous
// pass tests/threads/alarm-priority
// pass tests/threads/alarm-zero
// pass tests/threads/alarm-negative
// pass tests/threads/priority-change
// pass tests/threads/priority-donate-one
// pass tests/threads/priority-donate-multiple
// pass tests/threads/priority-donate-multiple2
// pass tests/threads/priority-donate-nest
// pass tests/threads/priority-donate-sema
// pass tests/threads/priority-donate-lower
// pass tests/threads/priority-fifo
// pass tests/threads/priority-preempt
// pass tests/threads/priority-sema
// pass tests/threads/priority-condvar
// pass tests/threads/priority-donate-chain
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "lib/stdio.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void check_address(void *addr);
void get_argument(void *rsp, int *arg, int count);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
// int fork(const char *thread_name);
int fork(const char *name, struct intr_frame *if_ );
int exec(const char *file);
int wait(int pid);

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
        halt();
        break;
    case SYS_EXIT:
        exit(f->R.rdi);
        break;
    case SYS_FORK:
        f->R.rax = fork(f->R.rdi, f);
        break;
    case SYS_EXEC:
        f->R.rax = exec(f->R.rdi); 
        break;
    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);
        break;
    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;
    case SYS_REMOVE:
        f->R.rax = remove (f->R.rdi);
        break;
    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;
    case SYS_FILESIZE:
        f->R.rax = filesize (f->R.rdi);
        break;
    case SYS_READ:
        f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_WRITE:
        f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_SEEK:
        seek (f->R.rdi, f->R.rsi);
        break;
    case SYS_TELL:
        f->R.rax = tell (f->R.rdi);
        break;
    case SYS_CLOSE:
        close (f->R.rdi);
        break;

    default:
	    // thread_exit ();
        break;
    }
}

void check_address (void *addr) {
    if (is_kernel_vaddr(addr)) 
        exit(-1);
    if (addr == NULL) 
        exit(-1);
    //! user영역이라도 할당되지 않을 수 있으니 pml4_get_page 함수를 통해서 할당 되어있는지 확인
    if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}


// void get_argument(void *rsp, int *arg, int count) {
//     check_address(&rsp);
//     // 시스템 콜 인자를 커널에 복사
//     // TODO: rsp에 count(argc)만큼의 데이터를 arg에 저장
//     // TODO: 스택 포인터를 참조하여 count만큼 스택에 저장된 인자들을 arg배열로 복사
//     rsp = rsp + 8; // return 값 빼기위해 +8
//     for (int i = 0; i < count; i++) {
//         arg[i] = rsp;
//         rsp += 8; // pointer 는 8바이트이니까 +8
//     }
// }

void halt (void) {
    power_off();
}

void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;
    printf("%s: exit(%d)\n", curr->name, status);

    // process_exit()은 thread_exit()통해 불려짐
    thread_exit();
}


int exec(const char *cmd_line) {
    // process_create_initd와 비슷하지만, thread_create은 fork에서 진행할 예정
    check_address(cmd_line);

    char *cmd_line_copy = palloc_get_page(0);
    if (cmd_line_copy == NULL)
        exit(-1);

    strlcpy(cmd_line_copy, &cmd_line, PGSIZE);
    
    if (process_exec(cmd_line_copy) == -1)
        exit(-1);
}

int fork(const char *name, struct intr_frame *if_ ) {
    return process_fork(name, if_);
}

int wait(int pid) {
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
    check_address(file);
    return filesys_create(file, initial_size);
}

bool remove (const char *file) {
    check_address(file);
    return filesys_remove(file);
}

int open (const char *file) {
    check_address(file);
    struct file *opened_file = filesys_open(file);
    if (opened_file == NULL)
        return -1;
    int file_fd = process_add_file(opened_file);
    if (file_fd == -1)
        file_close(opened_file);

    return file_fd;
    
}

int filesize (int fd) {
    struct file *file = process_get_file(fd);
    if (file == NULL)
        return -1;
    return file_length(file);
}

int read (int fd, void *buffer, unsigned length) {
    check_address(buffer);
    check_address(buffer + length - 1); //! buffer 끝 주소도 user영역에 있는지 확인
    int read_bytes;
    char *buf = (char *)buffer;

    if (fd == 0) {
        for (read_bytes = 0; read_bytes < length; read_bytes++) {
            *buf++ = input_getc();
            // printf("✅✅✅✅✅✅✅%d\n", read_bytes);
        }
    }
    else if (fd == 1) {
        return -1;
    }
    else {
        struct file *file = process_get_file(fd);
        
        if (file == NULL) {
           return -1;
        }
        lock_acquire(&filesys_lock);
        read_bytes = file_read(file, buffer, length);
        // printf("✅✅✅✅✅✅✅%d\n", read_bytes);
        lock_release(&filesys_lock);
    }

    return read_bytes;
    // char *ptr = (char *)buffer;
	// int bytes_read = 0;

	// lock_acquire(&filesys_lock);
	// if (fd == STDIN_FILENO)
	// {
	// 	for (int i = 0; i < length; i++)
	// 	{
	// 		*ptr++ = input_getc();
	// 		bytes_read++;
	// 	}
	// 	lock_release(&filesys_lock);
	// }
	// else
	// {
	// 	if (fd < 2)
	// 	{

	// 		lock_release(&filesys_lock);
	// 		return -1;
	// 	}
	// 	struct file *file = process_get_file(fd);
	// 	if (file == NULL)
	// 	{

	// 		lock_release(&filesys_lock);
	// 		return -1;
	// 	}
	// 	bytes_read = file_read(file, buffer, length);
	// 	lock_release(&filesys_lock);
	// }
	// return bytes_read;
}

int
write (int fd, const void *buffer, unsigned size) {
    check_address(buffer);
    check_address(buffer + size - 1);
	int bytes_write = 0;
	if (fd == 1) {
		putbuf(buffer, size);
		bytes_write = size;
	}
	else {
		if (fd < 2)
			return -1;
		struct file *file = process_get_file(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_write = file_write(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_write;
}
void seek (int fd, unsigned position) {
    struct file *file = process_get_file(fd);
    
    if (file == NULL) {
        return;
    }
    file_seek(file, position);
}

unsigned tell (int fd) {
    struct file *file = process_get_file(fd);
    
    if (file == NULL) {
        return;
    }
    return file_tell(file);
}
void close (int fd) {
    struct file *file = process_get_file(fd);
    // printf("✅✅✅✅✅✅✅%p\n", &file);
    if (file == NULL) {
        return;
    }
    file_close(file);
    process_close_file(fd);
}
