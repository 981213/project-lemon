/***************************************************************************
    This file is part of Project Lemon
    Copyright (C) 2011 Zhipeng Jia

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
***************************************************************************/

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

int pid;


uid_t run_uid, uj_uid;
gid_t run_gid, uj_gid;

#define tv2s(tv) ((float)tv.tv_usec / 1000000 + tv.tv_sec)

#ifdef __x86_64__
typedef unsigned long long int reg_val_t;
#define REG_SYSCALL orig_rax
#define REG_RET rax
#define REG_ARG0 rdi
#define REG_ARG1 rsi
#define REG_ARG2 rdx
#define REG_ARG3 rcx
#else
typedef long int reg_val_t;
#define REG_SYSCALL orig_eax
#define REG_RET eax
#define REG_ARG0 ebx
#define REG_ARG1 ecx
#define REG_ARG2 edx
#define REG_ARG3 esx
#endif

int check_safe_syscall(pid_t pid) {
    struct user_regs_struct reg;
    ptrace(PTRACE_GETREGS, pid, NULL, &reg);

    int syscall = (int)reg.REG_SYSCALL;

    if (0 > syscall || syscall >= 1000)  {
        return 0;
    }
    switch(syscall) {
    #if 0
    case __NR_vfork:
    case __NR_fork:
    case __NR_wait4:
    case __NR_setrlimit:
    case __NR_clone:
    case __NR_pipe:
    case __NR_chmod:
    case __NR_chdir:
    case __NR_fchdir:
        return 0;
    case __NR_execve:
    #endif
    default:
        return 1;
    }
}

void cleanUp() {
    kill(pid, SIGKILL);
    exit(0);
}

int main(int argc, char *argv[]) {
    int ptrace_opt = PTRACE_O_TRACESYSGOOD;
    ptrace_opt |= PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    ptrace_opt |= PTRACE_O_TRACEEXEC;
    int p_mode = 0;
    int exec_time = 0;
    int sig;
    pid_t wpid;

    int timeLimit, memoryLimit;
    sscanf(argv[5], "%d", &timeLimit);
    timeLimit = (timeLimit - 1) / 1000 + 1;
    sscanf(argv[6], "%d", &memoryLimit);
    memoryLimit *= 1024 * 1024;

    pid = fork();
    if (pid > 0) {
        signal(SIGINT, cleanUp);
        signal(SIGABRT, cleanUp);
        signal(SIGTERM, cleanUp);
        struct rusage usage;
        int status;
        while(1) {
            wpid = wait4(-1, &status, __WALL, &usage);
            if(wpid != pid) {
                kill(pid,SIGKILL);
                break;
            }
            if (WIFSTOPPED(status)) {
                sig = WSTOPSIG(status);

                if (p_mode == 0) {
                    if (sig == SIGTRAP) {
                        if (ptrace(PTRACE_SETOPTIONS, pid, NULL, ptrace_opt) == -1) {
                            fprintf(stderr, "Unable to set trace option!\n");
                            kill(pid,SIGKILL);
                            exit(255);
                        }
                    }
                    sig = 0;
                    p_mode = 1;
                } else if (sig == (SIGTRAP | 0x80)) {
                    if(!check_safe_syscall(pid)) kill(pid, SIGABRT);
                    sig = 0;
                } else if (sig == SIGTRAP) {
                    switch ((status >> 16) & 0xffff) {
                    case PTRACE_EVENT_CLONE:
                    case PTRACE_EVENT_FORK:
                    case PTRACE_EVENT_VFORK:
                        sig = 0;
                        kill(pid,SIGABRT);
                        break;
                    case PTRACE_EVENT_EXEC: /* in C or Pascal we shouldn't allow exec */
                        if(exec_time != 0) {
                            kill(pid,SIGABRT);
                            sig = 0;
                            break;
                        }
                        exec_time++;
                    case 0:
                        break;
                    }
                }
                ptrace(PTRACE_SYSCALL, pid, NULL, sig);
            } else {
                break;
            }

        }

        if(WIFSTOPPED(status)) {
            wait4(pid, &status, 0, &usage);
        }
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 1) return 1;
            printf("%d\n", (int)(usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000));
            printf("%d\n", (int)(usage.ru_maxrss) * 1024);
            if (WEXITSTATUS(status) != 0) return 2;
            return 0;
        }
        if (WIFSIGNALED(status)) {
            printf("%d\n", (int)(usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000));
            printf("%d\n", (int)(usage.ru_maxrss) * 1024);
            if (WTERMSIG(status) == SIGXCPU) return 3;
            if (WTERMSIG(status) == SIGKILL) return 4;
            if (WTERMSIG(status) == SIGABRT) return 4;
            return 2;
        }
    } else {
        if (strlen(argv[2]) > 0) freopen(argv[2], "r", stdin);
        if (strlen(argv[3]) > 0) freopen(argv[3], "w", stdout);
        if (strlen(argv[4]) > 0) freopen(argv[4], "w", stderr);
        if (memoryLimit != -1) {
            setrlimit(RLIMIT_AS, &(struct rlimit) {
                memoryLimit, memoryLimit
            });
            setrlimit(RLIMIT_DATA, &(struct rlimit) {
                memoryLimit, memoryLimit
            });
            setrlimit(RLIMIT_STACK, &(struct rlimit) {
                memoryLimit, memoryLimit
            });
        }
        setrlimit(RLIMIT_CPU, &(struct rlimit) {
            timeLimit, timeLimit + 1
        });
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            return 1;
        }
        if ((execlp("bash", "bash", "-c", argv[1], NULL) == -1)) {
            return 1;
        }
    }

    return 0;
}
