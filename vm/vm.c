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
// pass tests/userprog/close-normal
// pass tests/userprog/close-twice
// pass tests/userprog/close-bad-fd
// pass tests/userprog/read-normal
// pass tests/userprog/read-bad-ptr
// pass tests/userprog/read-boundary
// pass tests/userprog/read-zero
// pass tests/userprog/read-stdout
// pass tests/userprog/read-bad-fd
// pass tests/userprog/write-normal
// pass tests/userprog/write-bad-ptr
// pass tests/userprog/write-boundary
// pass tests/userprog/write-zero
// pass tests/userprog/write-stdin
// pass tests/userprog/write-bad-fd
// pass tests/userprog/fork-once
// pass tests/userprog/fork-multiple
// pass tests/userprog/fork-recursive
// pass tests/userprog/fork-read
// pass tests/userprog/fork-close
// pass tests/userprog/fork-boundary
// pass tests/userprog/exec-once
// pass tests/userprog/exec-arg
// pass tests/userprog/exec-boundary
// pass tests/userprog/exec-missing
// pass tests/userprog/exec-bad-ptr
// pass tests/userprog/exec-read
// pass tests/userprog/wait-simple
// pass tests/userprog/wait-twice
// pass tests/userprog/wait-killed
// pass tests/userprog/wait-bad-pid
// pass tests/userprog/multi-recurse
// pass tests/userprog/multi-child-fd
// pass tests/userprog/rox-simple
// pass tests/userprog/rox-child
// pass tests/userprog/rox-multichild
// pass tests/userprog/bad-read
// pass tests/userprog/bad-write
// pass tests/userprog/bad-read2
// pass tests/userprog/bad-write2
// pass tests/userprog/bad-jump
// pass tests/userprog/bad-jump2
// pass tests/vm/pt-grow-stack
// pass tests/vm/pt-grow-bad
// pass tests/vm/pt-big-stk-obj
// pass tests/vm/pt-bad-addr
// pass tests/vm/pt-bad-read
// pass tests/vm/pt-write-code
// pass tests/vm/pt-write-code2
// pass tests/vm/pt-grow-stk-sc
// pass tests/vm/page-linear
// pass tests/vm/page-parallel
// pass tests/vm/page-merge-seq
// pass tests/vm/page-merge-par
//! FAIL tests/vm/page-merge-stk
// FAIL tests/vm/page-merge-mm
// pass tests/vm/page-shuffle
// pass tests/vm/mmap-read
// pass tests/vm/mmap-close
// pass tests/vm/mmap-unmap
// pass tests/vm/mmap-overlap
// pass tests/vm/mmap-twice
// FAIL tests/vm/mmap-write
// pass tests/vm/mmap-ro
// pass tests/vm/mmap-exit
// pass tests/vm/mmap-shuffle
// pass tests/vm/mmap-bad-fd
// pass tests/vm/mmap-clean
// FAIL tests/vm/mmap-inherit
// pass tests/vm/mmap-misalign
// pass tests/vm/mmap-null
// pass tests/vm/mmap-over-code
// pass tests/vm/mmap-over-data
// pass tests/vm/mmap-over-stk
// pass tests/vm/mmap-remove
// pass tests/vm/mmap-zero
// pass tests/vm/mmap-bad-fd2
// pass tests/vm/mmap-bad-fd3
// pass tests/vm/mmap-zero-len
// FAIL tests/vm/mmap-off
// pass tests/vm/mmap-bad-off
// FAIL tests/vm/mmap-kernel
// pass tests/vm/lazy-file
// pass tests/vm/lazy-anon
// FAIL tests/vm/swap-file
// FAIL tests/vm/swap-anon
// FAIL tests/vm/swap-iter
// pass tests/vm/swap-fork
// pass tests/filesys/base/lg-create
// pass tests/filesys/base/lg-full
// pass tests/filesys/base/lg-random
// pass tests/filesys/base/lg-seq-block
// pass tests/filesys/base/lg-seq-random
// pass tests/filesys/base/sm-create
// pass tests/filesys/base/sm-full
// pass tests/filesys/base/sm-random
// pass tests/filesys/base/sm-seq-block
// pass tests/filesys/base/sm-seq-random
//! FAIL tests/filesys/base/syn-read
// pass tests/filesys/base/syn-remove
// pass tests/filesys/base/syn-write
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
// FAIL tests/vm/cow/cow-simple
// 9 / 141
// page-merge-stk, syn-read 가 pass와 FAIL 같이 나옴
/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/thread.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "threads/interrupt.h"
//! frame table 생성
struct list *frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
    list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
    //! upage = user virtual address
    // vm_initializer는 load_segment에서 불리고 lazy_load_segment함수를 인자로 넣어줌
    // vm_initializer = lazy_load_segment (process.c)
	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	/* Check wheter the upage is already occupied or not. */
    // 가상 주소 upage가 속한 페이지가 spt에 있는지 확인
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
        // upage에 페이지 할당이 안되있으므로 새 페이지 할당 및 uninit_new()를 통해 초기화
        struct page *p = (struct page *)malloc(sizeof(struct page));
        //! vm_type 관련 함수 구조체 설정
        typedef bool (*initializer) (struct page *, enum vm_type , void *);
        // initializer type 설정
        initializer which_initializer = NULL;
        

        switch (VM_TYPE(type)) {
            case VM_ANON:  
                which_initializer = anon_initializer;
                break;
            case VM_FILE:  
                which_initializer = file_backed_initializer;
                break;
	    }
        uninit_new(p, upage, init, type, aux, which_initializer);	
        // page를 초기화했으므로 새로 만들었던 writable을 저장 (uninit_new뒤에 modifiy)
        if (VM_MARKER_1_CHECK(type))
            p->mmap_origin = true;
        p->writable = writable;
		/* TODO: Insert the page into the spt. */
        return spt_insert_page(spt, p);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = (struct page*)malloc(sizeof(struct page));
    // struct page *page = NULL;
    struct hash_elem *e;
    // pg_round_down을 통해 해당 가상주소의 페이지 첫주소로 page의 va 저장
    page->va = pg_round_down(va);
    // hash_find를 통해 page_elem을 e로 저장
    e = hash_find(&spt->spt_type_hash, &page->page_elem);

    free(page);

    if (e == NULL)
        return NULL;
    // 해당 page_elem의 page 리턴
    return hash_entry(e, struct page, page_elem);
   
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	// int succ = false;
	// return succ;
    // hash_insert의 리턴값이  NULL이면 insert가 잘 된 것
    // spt에 현재 추가하려는 va를 가진 page가 있는지 확인
    struct page *p = spt_find_page(spt, page->va); 
	if (p != NULL)
		return false;
    if (hash_insert(&spt->spt_type_hash, &page->page_elem) == NULL) 
        return true;
    else
        return false;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
// queue방식으로 프레임 테이블 사용하겠음
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));

    frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
    if (frame->kva) {
        //! list 넣는것 생각해보기
        //! Kernel panic in run: PANIC at ../../lib/kernel/list.c:89 in list_end(): assertion `list != NULL' failed.
        // list_push_back(frame_table, &frame->frame_elem);
    }
    else {
        PANIC("todo");
        // frame = vm_evict_frame();
    }

    frame->page = NULL;
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
    struct thread *curr = thread_current();
	struct supplemental_page_table *spt = &curr->spt;
	struct page *page = NULL;
    uintptr_t rsp_ = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
    // fault난 주소에 해당하는 struct page가 spt_find_page를 통해, spt를 참조하라.
    if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

    if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
    {
        // user mode 혹은 kernel mode 구별 (syscall.c에 thread->rsp 작성함)
        rsp_ = f->rsp;
        if (!user) {
            rsp_ = curr->rsp_;
        }
        // addr이 유저스택 최대 크기 1MB 안으로 들어오는지
        if (addr <= USER_STACK && addr > USER_STACK_BOTTOM) {
            if (rsp_ - 8 > USER_STACK_BOTTOM && addr == rsp_ - 8)
                vm_stack_growth(addr);
            else if (rsp_ > USER_STACK_BOTTOM && addr >= rsp_)
                vm_stack_growth(addr);
        }

        page = spt_find_page(spt, addr);
        if (!page)
            return false;
        if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
            return false;
        return vm_do_claim_page(page);
    }
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;

    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

    struct thread *curr = thread_current();
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// pml4_set_page(curr->pml4, page->va, frame->kva, page->writable);
    // return swap_in (page, frame->kva); // swap_in은 bool 타입
    if (pml4_get_page(curr->pml4, page->va) == NULL && pml4_set_page(curr->pml4, page->va, frame->kva, page->writable))
        return swap_in (page, frame->kva); // swap_in은 bool 타입
    return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt ) {
    hash_init(&spt->spt_type_hash, hash_hash, hash_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
    // src -> dst
    struct hash *h = &src->spt_type_hash;
    // struct list **buckets = applier->buckets;
    // for (struct list_elem *e = list_begin(buckets); e != list_end(buckets); e = list_next(e))
	// {
		// struct hash_elem *hash_e = list_elem_to_hash_elem(e);
    //! hash.c line 170에 설명되어있음!!!! 함수를 잘 확인하자!!!
    struct hash_iterator i;
    hash_first(&i, h);
    while (hash_next(&i) != NULL){
		struct page *p = hash_entry(hash_cur(&i), struct page, page_elem);

        enum vm_type type = p->operations->type;
        void *upage = p->va;
        bool writable = p->writable;

        if (type == VM_UNINIT) {
            vm_alloc_page_with_initializer(VM_ANON, upage, writable, p->uninit.init, p->uninit.aux);
        }
        else {
            vm_alloc_page(type, upage, writable);
            if (type == VM_ANON) {
                // 추후 eviction 진행 후 상황에 따라 사용
            }
            vm_claim_page(upage);

            struct page *dst_p = spt_find_page(dst, upage);
            // 여기서 memcpy를 이용해 frame 복사
            memcpy(dst_p->frame->kva, p->frame->kva, PGSIZE);
        }
	}
    // printf("✅✅✅✅✅✅\n");
    return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
    // spt를 삭제하고 수정된 모든 내용을 스토리지에 다시 기록
    // 프로세스가 종료될 때 호출
    struct hash *h = &spt->spt_type_hash;
    hash_clear(h, spt_destructor);
}

//! add function
uint64_t hash_hash (const struct hash_elem *e, void *aux UNUSED) {
    struct page *current_page = hash_entry(e, struct page, page_elem);
    return hash_bytes(&current_page->va, sizeof(current_page->va));
}
// a < b = true (va로)
bool hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct page *page_a = hash_entry(a, struct page, page_elem);
    struct page *page_b = hash_entry(b, struct page, page_elem);
    return page_a->va < page_b->va;
}

void spt_destructor (struct hash_elem *hash_e, void *aux) {
    struct page *p = hash_entry(hash_e, struct page, page_elem);
    vm_dealloc_page(p); 
}