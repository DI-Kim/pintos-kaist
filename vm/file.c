/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
//* file-backed 페이지에 대한 함수 포인터 테이블, 수정 금지
static const struct page_operations file_ops = { 
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
    // 예상치 못한 close 방지용으로 복사 후 사용
    struct file *f = file_reopen(file);
    while (length > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_length bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_length = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_length;


		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, NULL, NULL))
			return false;

		/* Advance. */
		length -= page_length;
		addr += PGSIZE;
        offset += page_length;
	}
	return true;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
