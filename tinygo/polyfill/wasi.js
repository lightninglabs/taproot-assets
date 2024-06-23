function _define_property(obj, key, value) {
    if (key in obj) {
        Object.defineProperty(obj, key, {
            value: value,
            enumerable: true,
            configurable: true,
            writable: true
        })
    } else {
        obj[key] = value
    }
    return obj
}

import *as wasi from './wasi_defs.js';
import {debug} from './debug.js';

export class WASIProcExit extends Error {
    constructor(code) {
        super('exit with exit code ' + code);
        _define_property(this, 'code', void 0);
        this.code = code
    }
}

let WASI = class WASI {
    start(instance) {
        this.inst = instance;
        try {
            instance.exports._start();
            return 0
        } catch (e) {
            if (e instanceof WASIProcExit) {
                return e.code
            } else {
                throw e
            }
        }
    }

    initialize(instance) {
        this.inst = instance;
        instance.exports._initialize()
    }

    constructor(args, env, fds, options = {}) {
        _define_property(this, 'args', []);
        _define_property(this, 'env', []);
        _define_property(this, 'fds', []);
        _define_property(this, 'inst', void 0);
        _define_property(this, 'wasiImport', void 0);
        debug.enable(options.debug);
        this.args = args;
        this.env = env;
        this.fds = fds;
        const self = this;
        this.wasiImport = {
            args_sizes_get(argc, argv_buf_size) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                buffer.setUint32(argc, self.args.length, true);
                let buf_size = 0;
                for (const arg of self.args) {
                    buf_size += arg.length + 1
                }
                buffer.setUint32(argv_buf_size, buf_size, true);
                debug.log(buffer.getUint32(argc, true), buffer.getUint32(argv_buf_size, true));
                return 0
            },
            args_get(argv, argv_buf) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                const orig_argv_buf = argv_buf;
                for (let i = 0; i < self.args.length; i++) {
                    buffer.setUint32(argv, argv_buf, true);
                    argv += 4;
                    const arg = new TextEncoder().encode(self.args[i]);
                    buffer8.set(arg, argv_buf);
                    buffer.setUint8(argv_buf + arg.length, 0);
                    argv_buf += arg.length + 1
                }
                if (debug.enabled) {
                    debug.log(new TextDecoder('utf-8').decode(buffer8.slice(orig_argv_buf, argv_buf)))
                }
                return 0
            },
            environ_sizes_get(environ_count, environ_size) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                buffer.setUint32(environ_count, self.env.length, true);
                let buf_size = 0;
                for (const environ of self.env) {
                    buf_size += environ.length + 1
                }
                buffer.setUint32(environ_size, buf_size, true);
                debug.log(buffer.getUint32(environ_count, true), buffer.getUint32(environ_size, true));
                return 0
            },
            environ_get(environ, environ_buf) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                const orig_environ_buf = environ_buf;
                for (let i = 0; i < self.env.length; i++) {
                    buffer.setUint32(environ, environ_buf, true);
                    environ += 4;
                    const e = new TextEncoder().encode(self.env[i]);
                    buffer8.set(e, environ_buf);
                    buffer.setUint8(environ_buf + e.length, 0);
                    environ_buf += e.length + 1
                }
                if (debug.enabled) {
                    debug.log(new TextDecoder('utf-8').decode(buffer8.slice(orig_environ_buf, environ_buf)))
                }
                return 0
            },
            clock_res_get(id, res_ptr) {
                let resolutionValue;
                switch (id) {
                    case wasi.CLOCKID_MONOTONIC: {
                        resolutionValue = 5000n;
                        break
                    }
                    case wasi.CLOCKID_REALTIME: {
                        resolutionValue = 1000000n;
                        break
                    }
                    default:
                        return wasi.ERRNO_NOSYS
                }
                const view = new DataView(self.inst.exports.memory.buffer);
                view.setBigUint64(res_ptr, resolutionValue, true);
                return wasi.ERRNO_SUCCESS
            },
            clock_time_get(id, precision, time) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                if (id === wasi.CLOCKID_REALTIME) {
                    buffer.setBigUint64(time, BigInt(new Date().getTime()) * 1000000n, true)
                } else if (id == wasi.CLOCKID_MONOTONIC) {
                    let monotonic_time;
                    try {
                        monotonic_time = BigInt(Math.round(performance.now() * 1e6))
                    } catch (e) {
                        monotonic_time = 0n
                    }
                    buffer.setBigUint64(time, monotonic_time, true)
                } else {
                    buffer.setBigUint64(time, 0n, true)
                }
                return 0
            },
            fd_advise(fd, offset, len, advice) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_advise(offset, len, advice)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_allocate(fd, offset, len) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_allocate(offset, len)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_close(fd) {
                if (self.fds[fd] != undefined) {
                    const ret = self.fds[fd].fd_close();
                    self.fds[fd] = undefined;
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_datasync(fd) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_datasync()
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_fdstat_get(fd, fdstat_ptr) {
                if (self.fds[fd] != undefined) {
                    const {ret, fdstat} = self.fds[fd].fd_fdstat_get();
                    if (fdstat != null) {
                        fdstat.write_bytes(new DataView(self.inst.exports.memory.buffer), fdstat_ptr)
                    }
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_fdstat_set_flags(fd, flags) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_fdstat_set_flags(flags)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_fdstat_set_rights(fd, fs_rights_base, fs_rights_inheriting) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_fdstat_set_rights(fs_rights_base, fs_rights_inheriting)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_filestat_get(fd, filestat_ptr) {
                if (self.fds[fd] != undefined) {
                    const {ret, filestat} = self.fds[fd].fd_filestat_get();
                    if (filestat != null) {
                        filestat.write_bytes(new DataView(self.inst.exports.memory.buffer), filestat_ptr)
                    }
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_filestat_set_size(fd, size) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_filestat_set_size(size)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_filestat_set_times(fd, atim, mtim, fst_flags) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_filestat_set_times(atim, mtim, fst_flags)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_pread(fd, iovs_ptr, iovs_len, offset, nread_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const iovecs = wasi.Iovec.read_bytes_array(buffer, iovs_ptr, iovs_len);
                    const {
                        ret,
                        nread
                    } = self.fds[fd].fd_pread(buffer8, iovecs, offset);
                    buffer.setUint32(nread_ptr, nread, true);
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_prestat_get(fd, buf_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const {ret, prestat} = self.fds[fd].fd_prestat_get();
                    if (prestat != null) {
                        prestat.write_bytes(buffer, buf_ptr)
                    }
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_prestat_dir_name(fd, path_ptr, path_len) {
                if (self.fds[fd] != undefined) {
                    const {
                        ret,
                        prestat_dir_name
                    } = self.fds[fd].fd_prestat_dir_name();
                    if (prestat_dir_name != null) {
                        const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                        buffer8.set(prestat_dir_name, path_ptr)
                    }
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_pwrite(fd, iovs_ptr, iovs_len, offset, nwritten_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const iovecs = wasi.Ciovec.read_bytes_array(buffer, iovs_ptr, iovs_len);
                    const {
                        ret,
                        nwritten
                    } = self.fds[fd].fd_pwrite(buffer8, iovecs, offset);
                    buffer.setUint32(nwritten_ptr, nwritten, true);
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_read(fd, iovs_ptr, iovs_len, nread_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const iovecs = wasi.Iovec.read_bytes_array(buffer, iovs_ptr, iovs_len);
                    const {ret, nread} = self.fds[fd].fd_read(buffer8, iovecs);
                    buffer.setUint32(nread_ptr, nread, true);
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_readdir(fd, buf, buf_len, cookie, bufused_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    let bufused = 0;
                    while (true) {
                        const {
                            ret,
                            dirent
                        } = self.fds[fd].fd_readdir_single(cookie);
                        if (ret != 0) {
                            buffer.setUint32(bufused_ptr, bufused, true);
                            return ret
                        }
                        if (dirent == null) {
                            break
                        }
                        if (buf_len - bufused < dirent.head_length()) {
                            bufused = buf_len;
                            break
                        }
                        const head_bytes = new ArrayBuffer(dirent.head_length());
                        dirent.write_head_bytes(new DataView(head_bytes), 0);
                        buffer8.set(new Uint8Array(head_bytes).slice(0, Math.min(head_bytes.byteLength, buf_len - bufused)), buf);
                        buf += dirent.head_length();
                        bufused += dirent.head_length();
                        if (buf_len - bufused < dirent.name_length()) {
                            bufused = buf_len;
                            break
                        }
                        dirent.write_name_bytes(buffer8, buf, buf_len - bufused);
                        buf += dirent.name_length();
                        bufused += dirent.name_length();
                        cookie = dirent.d_next
                    }
                    buffer.setUint32(bufused_ptr, bufused, true);
                    return 0
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_renumber(fd, to) {
                if (self.fds[fd] != undefined && self.fds[to] != undefined) {
                    const ret = self.fds[to].fd_close();
                    if (ret != 0) {
                        return ret
                    }
                    self.fds[to] = self.fds[fd];
                    self.fds[fd] = undefined;
                    return 0
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_seek(fd, offset, whence, offset_out_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const {
                        ret,
                        offset: offset_out
                    } = self.fds[fd].fd_seek(offset, whence);
                    buffer.setBigInt64(offset_out_ptr, offset_out, true);
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_sync(fd) {
                if (self.fds[fd] != undefined) {
                    return self.fds[fd].fd_sync()
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_tell(fd, offset_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const {ret, offset} = self.fds[fd].fd_tell();
                    buffer.setBigUint64(offset_ptr, offset, true);
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            fd_write(fd, iovs_ptr, iovs_len, nwritten_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const iovecs = wasi.Ciovec.read_bytes_array(buffer, iovs_ptr, iovs_len);
                    const {
                        ret,
                        nwritten
                    } = self.fds[fd].fd_write(buffer8, iovecs);
                    buffer.setUint32(nwritten_ptr, nwritten, true);
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_create_directory(fd, path_ptr, path_len) {
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const path = new TextDecoder('utf-8').decode(buffer8.slice(path_ptr, path_ptr + path_len));
                    return self.fds[fd].path_create_directory(path)
                }
            },
            path_filestat_get(fd, flags, path_ptr, path_len, filestat_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const path = new TextDecoder('utf-8').decode(buffer8.slice(path_ptr, path_ptr + path_len));
                    const {
                        ret,
                        filestat
                    } = self.fds[fd].path_filestat_get(flags, path);
                    if (filestat != null) {
                        filestat.write_bytes(buffer, filestat_ptr)
                    }
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_filestat_set_times(fd, flags, path_ptr, path_len, atim, mtim, fst_flags) {
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const path = new TextDecoder('utf-8').decode(buffer8.slice(path_ptr, path_ptr + path_len));
                    return self.fds[fd].path_filestat_set_times(flags, path, atim, mtim, fst_flags)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_link(old_fd, old_flags, old_path_ptr, old_path_len, new_fd, new_path_ptr, new_path_len) {
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[old_fd] != undefined && self.fds[new_fd] != undefined) {
                    const old_path = new TextDecoder('utf-8').decode(buffer8.slice(old_path_ptr, old_path_ptr + old_path_len));
                    const new_path = new TextDecoder('utf-8').decode(buffer8.slice(new_path_ptr, new_path_ptr + new_path_len));
                    return self.fds[new_fd].path_link(old_fd, old_flags, old_path, new_path)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_open(fd, dirflags, path_ptr, path_len, oflags, fs_rights_base, fs_rights_inheriting, fd_flags, opened_fd_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const path = new TextDecoder('utf-8').decode(buffer8.slice(path_ptr, path_ptr + path_len));
                    debug.log(path);
                    const {
                        ret,
                        fd_obj
                    } = self.fds[fd].path_open(dirflags, path, oflags, fs_rights_base, fs_rights_inheriting, fd_flags);
                    if (ret != 0) {
                        return ret
                    }
                    self.fds.push(fd_obj);
                    const opened_fd = self.fds.length - 1;
                    buffer.setUint32(opened_fd_ptr, opened_fd, true);
                    return 0
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_readlink(fd, path_ptr, path_len, buf_ptr, buf_len, nread_ptr) {
                const buffer = new DataView(self.inst.exports.memory.buffer);
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const path = new TextDecoder('utf-8').decode(buffer8.slice(path_ptr, path_ptr + path_len));
                    debug.log(path);
                    const {ret, data} = self.fds[fd].path_readlink(path);
                    if (data != null) {
                        const data_buf = new TextEncoder().encode(data);
                        if (data_buf.length > buf_len) {
                            buffer.setUint32(nread_ptr, 0, true);
                            return wasi.ERRNO_BADF
                        }
                        buffer8.set(data_buf, buf_ptr);
                        buffer.setUint32(nread_ptr, data_buf.length, true)
                    }
                    return ret
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_remove_directory(fd, path_ptr, path_len) {
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const path = new TextDecoder('utf-8').decode(buffer8.slice(path_ptr, path_ptr + path_len));
                    return self.fds[fd].path_remove_directory(path)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_rename(fd, old_path_ptr, old_path_len, new_fd, new_path_ptr, new_path_len) {
                throw 'FIXME what is the best abstraction for this?'
            },
            path_symlink(old_path_ptr, old_path_len, fd, new_path_ptr, new_path_len) {
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const old_path = new TextDecoder('utf-8').decode(buffer8.slice(old_path_ptr, old_path_ptr + old_path_len));
                    const new_path = new TextDecoder('utf-8').decode(buffer8.slice(new_path_ptr, new_path_ptr + new_path_len));
                    return self.fds[fd].path_symlink(old_path, new_path)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            path_unlink_file(fd, path_ptr, path_len) {
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                if (self.fds[fd] != undefined) {
                    const path = new TextDecoder('utf-8').decode(buffer8.slice(path_ptr, path_ptr + path_len));
                    return self.fds[fd].path_unlink_file(path)
                } else {
                    return wasi.ERRNO_BADF
                }
            },
            poll_oneoff(in_, out, nsubscriptions) {
                throw 'async io not supported'
            },
            proc_exit(exit_code) {
                throw new WASIProcExit(exit_code)
            },
            proc_raise(sig) {
                throw 'raised signal ' + sig
            },
            sched_yield() {
            },
            random_get(buf, buf_len) {
                const buffer8 = new Uint8Array(self.inst.exports.memory.buffer);
                for (let i = 0; i < buf_len; i++) {
                    buffer8[buf + i] = Math.random() * 256 | 0
                }
            },
            sock_recv(fd, ri_data, ri_flags) {
                throw 'sockets not supported'
            },
            sock_send(fd, si_data, si_flags) {
                throw 'sockets not supported'
            },
            sock_shutdown(fd, how) {
                throw 'sockets not supported'
            },
            sock_accept(fd, flags) {
                throw 'sockets not supported'
            }
        }
    }
};
export {WASI as default};