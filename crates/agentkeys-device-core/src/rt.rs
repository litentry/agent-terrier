//! Freestanding runtime for the standalone device staticlib (issue #367).
//!
//! A `no_std` `staticlib` is the root of its own link unit, so it must provide a
//! `#[panic_handler]` and a `#[global_allocator]` — `std` supplies these only on
//! the host (rlib) path. Compiled ONLY with `--features freestanding` (the
//! firmware's `cargo rustc --crate-type staticlib` build); the workspace rlib
//! never enables it, so there is no clash with `std`'s handlers.
//!
//! The allocator delegates to the C runtime's `aligned_alloc`/`free` — ESP-IDF
//! (newlib) and the host libc both provide them — so Rust's heap is the one
//! ESP-IDF already manages. Panics abort: the firmware links `panic = "abort"`
//! and has no unwinder.
#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

extern "C" {
    fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn abort() -> !;
}

struct CAlloc;

// C11 `aligned_alloc` requires the alignment to be a power of two ≥ sizeof(void*)
// and the size to be a multiple of the alignment; round both up to satisfy it.
unsafe impl GlobalAlloc for CAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(core::mem::size_of::<usize>());
        let size = (layout.size() + align - 1) & !(align - 1);
        aligned_alloc(align, size) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr as *mut c_void);
    }
}

#[global_allocator]
static ALLOCATOR: CAlloc = CAlloc;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { abort() }
}

// Unwinding is never exercised (the panic handler aborts), but dependency objects
// compiled with the default `panic = "unwind"` still emit a reference to the
// personality routine. A no-op stub resolves it at the final link — both here
// (C harness / ESP-IDF) and on the device — without rebuilding std with
// `-Z build-std=...,panic_abort`.
#[no_mangle]
extern "C" fn rust_eh_personality() {}
