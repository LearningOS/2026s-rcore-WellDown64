//! Process management syscalls
use crate::config::{PAGE_SIZE, TRAMPOLINE};
use crate::mm::{
    translated_byte_buffer, MapPermission, PTEFlags, PageTable, PhysPageNum, VirtAddr,
};
use crate::task::{
    change_program_brk, current_insert_frame_area, current_syscall_req_cnt, current_unmap_frame,
    current_user_token, exit_current_and_run_next, suspend_current_and_run_next,
};
use crate::timer::get_time_us;
use core::mem::size_of;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let mut ts_buf =
        translated_byte_buffer(current_user_token(), ts as *mut u8, size_of::<TimeVal>());
    let written_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    if ts_buf.len() == 1 {
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!(written_val) as *const u8,
                ts_buf[0].as_mut_ptr(),
                size_of::<TimeVal>(),
            );
        }
    } else if ts_buf.len() == 2 {
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!(written_val.sec) as *const u8,
                ts_buf[0].as_mut_ptr(),
                size_of::<usize>(),
            );
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!(written_val.usec) as *const u8,
                ts_buf[1].as_mut_ptr(),
                size_of::<usize>(),
            );
        }
    } else {
        panic!("Unkown error");
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    match trace_request {
        0 => {
            let v_addr: VirtAddr = id.into();
            let vpn = v_addr.floor();
            let token = current_user_token();
            let page_table = PageTable::from_token(token);
            if let Some(pte) = page_table.translate(vpn) {
                if !pte.is_valid() || !pte.readable() || !pte.flags().contains(PTEFlags::U) {
                    return -1;
                }
                let p_addr: usize =
                    <PhysPageNum as Into<usize>>::into(pte.ppn()) * 4096 + v_addr.page_offset();
                unsafe { core::ptr::read_volatile(p_addr as *const u8) as isize }
            } else {
                -1
            }
        }
        1 => {
            let v_addr: VirtAddr = id.into();
            let vpn = v_addr.floor();
            let token = current_user_token();
            let page_table = PageTable::from_token(token);
            if let Some(pte) = page_table.translate(vpn) {
                if !pte.is_valid() || !pte.writable() || !pte.flags().contains(PTEFlags::U) {
                    return -1;
                }
                let p_addr: usize =
                    <PhysPageNum as Into<usize>>::into(pte.ppn()) * 4096 + v_addr.page_offset();
                unsafe {
                    core::ptr::write_volatile(p_addr as *mut u8, data as u8);
                }
                0
            } else {
                -1
            }
        }
        2 => current_syscall_req_cnt(id),
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("kernel: sys_mmap");
    // `start` should be aligned with `PAGE_SIZE`
    if start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }
    if start >= TRAMPOLINE {
        return -1;
    }
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return -1,
    };
    if end > TRAMPOLINE {
        return -1;
    }

    // bit 0: Readable
    // bit 1: Writable
    // bit 2: Executable
    // Else must be 0
    if prot & !0x7 != 0 || prot & 0x7 == 0 {
        return -1;
    }

    let mut perm = MapPermission::U;
    if prot & 1 != 0 {
        perm |= MapPermission::R;
    }
    if prot & (1 << 1) != 0 {
        perm |= MapPermission::W;
    }
    if prot & (1 << 2) != 0 {
        perm |= MapPermission::X;
    }

    trace!("prot = {:#b}", prot);
    trace!("perm = {:?}", perm);

    current_insert_frame_area(start, start + len, perm)
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    // `start` should be aligned with `PAGE_SIZE`
    if start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }
    if start >= TRAMPOLINE {
        return -1;
    }
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return -1,
    };
    if end > TRAMPOLINE {
        return -1;
    }
    current_unmap_frame(start, end)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
