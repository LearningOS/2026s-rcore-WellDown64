//! Process management syscalls
//!
use alloc::sync::Arc;

use crate::{
    fs::{open_file, OpenFlags},
    mm::{translated_refmut, translated_str},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, current_insert_frame_area, current_unmap_frame,
    },
};
use crate::config::{PAGE_SIZE, TRAMPOLINE};
use crate::mm::{translated_byte_buffer, MapPermission};
use crate::timer::get_time_us;
use core::mem::size_of;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    //trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        task.exec(all_data.as_slice());
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    //trace!("kernel: sys_waitpid");
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
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
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    trace!( "kernel:pid[{}] sys_spawn", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);

    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        let child = task.spawn(all_data.as_slice());

        child.getpid() as isize
    } else {
        -1
    }
}

/// YOUR JOB: Set task priority.
pub fn sys_set_priority(prio: isize) -> isize {
    trace!( "kernel:pid[{}] sys_set_priority", current_task().unwrap().pid.0);
    if prio >= 2 {
        let task = current_task().unwrap();
        task.set_priority(prio);
        prio
    }
    else {
        -1
    }
}
