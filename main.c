#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

const char run_user_default[] = "securex";
const char secure_cookie[] = ".Xauthority-secure";

void usage(char* progname)
{
	printf("Usage %s -u [user] [PROGRAM]\n", progname);
	exit(0);
}

int main(int argc, char** argv)
{
	size_t progVstart = 1;
	const char *run_user = run_user_default;
	
	if(argc < 2)
		usage(argv[0]);
	
	uid_t user_uid = getuid();
	if(user_uid == 0)
	{
		printf("Do not run this programm as root\n");
		return -1;
	}

	uid_t euid = geteuid();
	if(euid != 0)
	{
		printf("This programm must be setuid as root\n");
		return -1;
	}

	const char* display = getenv("DISPLAY");
	if(display == NULL)
	{
		printf("DSIPLAY must be set\n");
		return -1;
	}

	if(strcmp(argv[1], "-u") == 0)
	{
		if(argc < 3)
			usage(argv[0]);
		progVstart+=1;
		run_user = getlogin();
	}

	struct passwd *securex_user = getpwnam(run_user);
	if(securex_user == NULL)
	{
		printf("user %s must exist\n", run_user);
		return -1;
	}
	
	char secure_cookie_filename[80]; 
	
	snprintf(secure_cookie_filename, sizeof(secure_cookie_filename),
			 "%s/%s", getenv("HOME") ?: "/root/", secure_cookie);
	
	if(access(secure_cookie_filename, F_OK) == 0)
		remove(secure_cookie_filename);
		
	pid_t pid = fork();
	if(pid == 0)
	{
		printf("Createing %s\n", secure_cookie_filename);
		if(setgid(securex_user->pw_gid) < 0)
		{
			printf("setgid failure\n");
			return -1;
		}
		if(setuid(user_uid) < 0)
		{
			printf("setuid failure\n");
			return -1;
		}
		
		int fd = open(secure_cookie_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if(fd < 0)
		{
			printf("can not create %s: %s\n", secure_cookie_filename, strerror(errno));
			return -1;
		}
		close(fd);
		execlp("xauth", "xauth", "-f", secure_cookie_filename, "generate", display, "MIT-MAGIC-COOKIE-1", "untrusted", (char*) NULL);
		printf("failed to exec xauth\n");
		return -1;
	}
	else if(pid == -1)
	{
		printf("fork() failure\n");
		return -1;
	}
	else
	{
		int retval;
		waitpid(pid, &retval, 0);
		if(retval != 0)
		{
			printf("xauth failure\n");
			return -1;
		}
		
		chmod(secure_cookie_filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	}
	
	pid = fork();
	if(pid == 0)
	{
		printf("Executeing %s\n", argv[progVstart]);
		if(setgid(securex_user->pw_gid) < 0)
		{
			printf("setgid failure\n");
			return -1;
		}
		if(setuid(securex_user->pw_uid) < 0)
		{
			printf("setuid failure\n");
			return -1;
		}
		if(setenv("XAUTHORITY", secure_cookie_filename, 1) < 0)
		{
			printf("can not setenv XAUTHORITY=%s: %s\n", secure_cookie_filename, strerror(errno));
			return -1;
		}
		execvp(argv[progVstart], &(argv[progVstart]));
		printf("failed to exec %s: %s\n", argv[progVstart], strerror(errno));
		return -1;
	}
	else if(pid == -1)
	{
		printf("fork() failure\n");
		return -1;
	}
	else
	{
		int retval;
		waitpid(pid, &retval, 0);
		return retval;
	}
	
	return -1;
}
