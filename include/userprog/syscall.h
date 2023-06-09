#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);

struct lock filesys_lock;

void check_address (void *addr);
void get_argument(void *rsp, int *arg, int count);

uint64_t halt (void);
void exit (int status);
// pid_t fork (const char *thread_name);
void fork(const char *name, struct intr_frame *if_ );
int exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

#endif /* userprog/syscall.h */
