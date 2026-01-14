#include "parser/ast.h"
#include "shell.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <pwd.h>

#define PIPE_RD 0
#define PIPE_WR 1

void initialize(void)
{
    if (signal(SIGINT, sigint_handler) == SIG_ERR)
        perror("sigint_handler error");
    if (prompt)
        prompt = generate_prompt();
}

void run_command(node_t *node)
{
    switch (node->type) {
        case NODE_COMMAND:
            handle_cmd(node);
            break;
        case NODE_SEQUENCE:
            handle_seq(node);
            break;
        case NODE_PIPE:
            handle_pipe(node);
            break;
        case NODE_DETACH:
            handle_detach(node);
            break;
        case NODE_SUBSHELL:
            handle_subshell(node);
            break;
        case NODE_REDIRECT:
            break;
    }

    if (prompt)
        prompt = generate_prompt();
}

void handle_cmd(node_t *node)
{
    char *program = node->command.program;
    char **argv = node->command.argv;
    size_t argc = node->command.argc;

    if (program == NULL)
        return;
    if (strcmp(program, "exit") == 0)
        handle_exit(argv, argc);
    else if (strcmp(program, "cd") == 0)
        handle_cd(argv, argc);
    else if (strcmp(program, "set") == 0)
        handle_set(argv, argc);
    else if (strcmp(program, "unset") == 0)
        handle_unset(argv, argc);
    else
        execute_cmd(program, argv);
}

void handle_seq(node_t *node)
{
    if (node->type != NODE_SEQUENCE)
        run_command(node);
    else  {
        handle_seq(node->sequence.first);
        handle_seq(node->sequence.second);
    }
}

void handle_pipe(node_t *node)
{
    int numCom = node->pipe.n_parts;
    int fd[2];
    int prev = -1;
    pid_t pid;

    for (int i = 0; i < numCom; i++) {
        if (pipe(fd) < 0) {
            perror("pipe error");
            return;
        }
        pid = fork();

        if (pid < 0) {
            perror("fork error");
            return;
        }
        else if (pid == 0) {
            if (prev != -1 ) {
                if (dup2(prev, STDIN_FILENO) < 0)
                    perror("dup2 error");
                close(fd[PIPE_RD]);
            }
            if (i < numCom - 1) {
                close(fd[PIPE_RD]);
                if (dup2(fd[PIPE_WR], STDOUT_FILENO) < 0)
                    perror("dup2 error");
                close(fd[PIPE_WR]);
            }
            run_command(node->pipe.parts[i]);
            exit(1);
        }
        if (prev != -1)
            close(prev);
        if (i < numCom - 1) {
            close(fd[PIPE_WR]);
            prev = fd[PIPE_RD];
        }
    }
    wait(NULL);
}

void handle_detach(node_t *node)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork error");
        return;
    }
    else if (pid == 0) {
        run_command(node->detach.child);
        exit(0);
    }
}

void handle_subshell(node_t *node)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork error");
        return;
    }
    else if (pid == 0) {
        run_command(node->subshell.child);
        exit(0);
    }
    else {
        int status;
        if (waitpid(pid, &status, 0) < 0)
            perror("waitpid error");
    }
}

char *generate_prompt()
{
    char *ps1 = getenv("PS1");
    if (ps1 == NULL)
        ps1 = "\\u@\\h:\\w$ ";

    const char *user = get_user();

    char host[HOST_NAME_MAX + 1];
    if (gethostname(host, sizeof(host)) != 0) {
        perror("HOSTNAME fail");
        exit(1);
    }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        perror("cwd error");
        exit(1);
    }

    char *localPrompt= malloc(strlen(user) + strlen(host) + strlen(cwd) + strlen(ps1) + 1);
    if (!localPrompt) {
        perror("malloc error");
        exit(1);
    }
    char *promptPtr = localPrompt;

    for (size_t i = 0; i < strlen(ps1); i++) {
        if (ps1[i] == '\\') {
            i++;
            switch (ps1[i]) {
                case 'u':
                    promptPtr += sprintf(promptPtr, "%s", user);
                    break;
                case 'h':
                    promptPtr += sprintf(promptPtr, "%s", host);
                    break;
                case 'w':
                    promptPtr += sprintf(promptPtr, "%s", cwd);
                    break;
                default:
                    *promptPtr++ = '\\';
                    *promptPtr++ = ps1[i];
                    break;
            }
        }
        else
            *promptPtr++ = ps1[i];
    }
    *promptPtr++ = ' ';
    *promptPtr = '\0';
    return localPrompt;
}

void sigint_handler() {
    if (prompt)
        printf("%s", prompt);
}

void handle_exit(char **argv, size_t argc) {
    int status = (argc > 1) ? atoi(argv[1]) : 0;
    exit(status);
}

void handle_cd(char **argv, size_t argc) {
    if (argc < 2) {
        char *home = getenv("HOME");
        if (home && chdir(home) != 0)
            perror("cd error");
    }
    else {
        if (chdir(argv[1]) != 0)
            perror("cd error");
    }
}

void handle_set(char **argv, size_t argc) {
    if (argc < 2) {
        fprintf(stderr, "set format error\n");
        return;
    }

    char *var = argv[1];
    char *delimiter = strchr(var, '=');
    if (!delimiter) {
        fprintf(stderr, "set format error\n");
        return;
    }
    *delimiter = '\0';
    char *name = var;
    char *value = delimiter + 1;

    if (setenv(name, value, 1) != 0)
        perror("set error");
}

void handle_unset(char **argv, size_t argc) {
    if (argc < 2) {
        fprintf(stderr, "unset format error\n");
        return;
    }
    if (unsetenv(argv[1]) != 0)
        perror("unset error");
}

void execute_cmd(char *program, char **argv) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork error");
        return;
    }
    else if (pid == 0) {
        if (signal(SIGINT, SIG_DFL) == SIG_ERR) {
            perror("SIGINT error");
            exit(1);
        }
        execvp(program, argv);
        perror("execvp error");
        exit(1);
    }
    else {
        int status;
        if (waitpid(pid, &status, 0) < 0)
            perror("waitpid error");
    }
}

char *get_user()
{
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        perror("get_user fail");
        exit(1);
    }
    return pw->pw_name;
}
