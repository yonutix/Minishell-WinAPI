/**
* Operating Systems 2013 - Assignment 1
*
*/


#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

/* do not use UNICODE */
#undef _UNICODE
#undef UNICODE

#define READ		0
#define WRITE		1

#define MAX_SIZE_ENVIRONMENT_VARIABLE 100

/**
* Debug method, used by DIE macro.
*/
static VOID PrintLastError(const PCHAR message)
{
  CHAR errBuff[1024];

  FormatMessage(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
    NULL,
    GetLastError(),
    0,
    errBuff,
    sizeof(errBuff) - 1,
    NULL);

  fprintf(stderr, "%s: %s\n", message, errBuff);
}

/**
* Internal change-directory command.
*/
static bool shell_cd(word_t *dir)
{
  /* TODO execute cd */

  return 0;
}

/**
* Internal exit/quit command.
*/
static int shell_exit()
{
  /* TODO execute exit/quit */

  return 0; /* TODO replace with actual exit code */
}

/**
* Concatenate parts of the word to obtain the command
*/
static LPTSTR get_word(word_t *s)
{
  DWORD string_length = 0;
  DWORD substring_length = 0;

  LPTSTR string = NULL;
  CHAR substring[MAX_SIZE_ENVIRONMENT_VARIABLE];

  DWORD dwret;

  while (s != NULL) {
    strcpy(substring, s->string);

    if (s->expand == true) {
      dwret = GetEnvironmentVariable(substring, substring, MAX_SIZE_ENVIRONMENT_VARIABLE);
      if (!dwret)
        /* Environment Variable does not exist. */
        strcpy(substring, "");
    }

    substring_length = strlen(substring);

    string = realloc(string, string_length + substring_length + 1);
    memset(string + string_length, 0, substring_length + 1);

    strcat(string, substring);
    string_length += substring_length;

    s = s->next_part;
  }

  return string;
}

/**
* Parse arguments in order to succesfully process them using CreateProcess
*/
static LPTSTR get_argv(simple_command_t *command)
{
  LPTSTR argv = NULL;
  LPTSTR substring = NULL;
  word_t *param;

  DWORD string_length = 0;
  DWORD substring_length = 0;

  argv = get_word(command->verb);
  assert(argv != NULL);

  string_length = strlen(argv);

  param = command->params;
  while (param != NULL) {
    substring = get_word(param);
    substring_length = strlen(substring);

    argv = realloc(argv, string_length + substring_length + 4);
    assert(argv != NULL);

    strcat(argv, " ");

    /* Surround parameters with ' ' */
    if(strchr(substring, '\"') != NULL){
      strcat(argv, "'");
      strcat(argv, substring);
      strcat(argv, "'");
    }
    else{
      strcat(argv, "\"");
      strcat(argv, substring);
      strcat(argv, "\"");
    }

    string_length += substring_length + 3;
    param = param->next_word;

    free(substring);
  }

  return argv;
}

static HANDLE FileOpen(LPCSTR filename, const char* mode)
{
  SECURITY_ATTRIBUTES sa;
  HANDLE hFile = INVALID_HANDLE_VALUE;

  ZeroMemory(&sa, sizeof(sa));
  sa.bInheritHandle = TRUE;

  if(strcmp(mode, "r") == 0){
    return CreateFile(
      filename,
      GENERIC_READ,
      FILE_SHARE_READ,
      (LPSECURITY_ATTRIBUTES)&sa,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  }

  if(strcmp(mode, "w") == 0){
    return CreateFile(
      filename,
      GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      (LPSECURITY_ATTRIBUTES)&sa,
      CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  }

  if(strcmp(mode, "a") == 0){
    hFile = CreateFile(
      filename,
      GENERIC_WRITE | FILE_APPEND_DATA,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      (LPSECURITY_ATTRIBUTES)&sa,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
    SetFilePointer(hFile, 0, NULL, FILE_END);
    return hFile;
  }
  return INVALID_HANDLE_VALUE;
}

static VOID InitStdHandles(STARTUPINFO *psi)
{
  psi->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  psi->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  psi->hStdError = GetStdHandle(STD_ERROR_HANDLE);
}

static VOID RedirectHandle(STARTUPINFO *psi, HANDLE hFile, INT opt)
{
  if (hFile == INVALID_HANDLE_VALUE)
    return;
  psi->dwFlags |= STARTF_USESTDHANDLES;
  /* TODO 1 - Redirect one of STDIN, STDOUT, STDERR to hFile */
  switch (opt) {
  case STD_INPUT_HANDLE:
    /* TODO 1 */
    psi->hStdInput = hFile;
    break;
  case STD_OUTPUT_HANDLE:
    /* TODO 1 */
    psi->hStdOutput = hFile;
    break;
  case STD_ERROR_HANDLE:
    /* TODO 1 */
    psi->hStdError = hFile;
    break;
  }
}

VOID redirrect_command(simple_command_t *s, STARTUPINFO *siStartupInfo, HANDLE *hInFile, HANDLE *hOutFile, HANDLE *hErrFile)
{
  InitStdHandles(siStartupInfo);
  if(s->in){
    *hInFile = FileOpen((LPCSTR)get_word(s->in), "r");
    RedirectHandle(siStartupInfo, *hInFile, STD_INPUT_HANDLE);
  }

  if(s->out && s->err){
    if(strcmp(get_word(s->out), get_word(s->err)) == 0){
      DeleteFile((LPCSTR)get_word(s->out));

      *hOutFile = FileOpen((LPCSTR)get_word(s->out), "a");
      RedirectHandle(siStartupInfo, *hOutFile, STD_OUTPUT_HANDLE);
      RedirectHandle(siStartupInfo, *hOutFile, STD_ERROR_HANDLE);
      return;
    }
  }

  if(s->out){
    if(s->io_flags & IO_OUT_APPEND){
      *hOutFile = FileOpen((LPCSTR)get_word(s->out), "a");
    }
    else{
      *hOutFile = FileOpen((LPCSTR)get_word(s->out), "w");
    }
    RedirectHandle(siStartupInfo, *hOutFile, STD_OUTPUT_HANDLE);
  }

  if(s->err){
    if(s->io_flags & IO_ERR_APPEND){
      *hErrFile = FileOpen((LPCSTR)get_word(s->err), "a");
    }
    else{
      *hErrFile = FileOpen((LPCSTR)get_word(s->err), "w");
    }
    RedirectHandle(siStartupInfo, *hErrFile, STD_ERROR_HANDLE);
  }
}

VOID close_handles(HANDLE hInFile, HANDLE hOutFile, HANDLE hErrFile)
{
  if(hOutFile != INVALID_HANDLE_VALUE){
    CloseHandle(hOutFile);
  }

  if(hInFile != INVALID_HANDLE_VALUE){
    CloseHandle(hInFile);
  }

  if(hErrFile != INVALID_HANDLE_VALUE){
    CloseHandle(hErrFile);
  }
}

int exec_simple_proc(simple_command_t *s,
  HANDLE hErrFile,
  SECURITY_ATTRIBUTES sa,
  STARTUPINFO siStartupInfo,
  PROCESS_INFORMATION piProcessInfo)
{
  char buffer[100];
  int x;
  char* cmd;
  BOOL ret;
  cmd = get_argv(s);
  ret = CreateProcess(NULL,
    (LPSTR)cmd,
    (LPSECURITY_ATTRIBUTES)&sa,
    NULL,
    TRUE,
    NORMAL_PRIORITY_CLASS,
    NULL,
    NULL,
    &siStartupInfo,
    &piProcessInfo);

  if(ret == FALSE){
    sprintf(buffer, "%s: No such file or directory\n", cmd);
    WriteFile(hErrFile, buffer, strlen(buffer), &x, NULL);
  }
  else{
    WaitForSingleObject(piProcessInfo.hProcess, INFINITE);

    GetExitCodeProcess(piProcessInfo.hProcess, &ret);

    CloseHandle(piProcessInfo.hProcess);
    CloseHandle(piProcessInfo.hThread);
  }
  free(cmd);
  return ret;
}

/**
* Parse and execute a simple command, by either creating a new processing or
* internally process it.
*/
bool parse_simple(simple_command_t *s, int level, command_t *father, HANDLE *h)
{
  BOOL ret;
  SECURITY_ATTRIBUTES sa;
  STARTUPINFO siStartupInfo;
  PROCESS_INFORMATION piProcessInfo;
  HANDLE hOutFile = INVALID_HANDLE_VALUE;
  HANDLE hInFile = INVALID_HANDLE_VALUE;
  HANDLE hErrFile = INVALID_HANDLE_VALUE;
  BOOL changed = FALSE;
  int f_ret;

  ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;

  ZeroMemory(&siStartupInfo, sizeof(siStartupInfo));
  ZeroMemory(&piProcessInfo, sizeof(piProcessInfo));

  siStartupInfo.cb = sizeof(siStartupInfo); 
  /* TODO sanity checks */

  if(s->verb->next_part != NULL){
    ret = SetEnvironmentVariable((LPCTSTR)s->verb->string, (LPCTSTR)s->verb->next_part->next_part->string);
    return ret-1;
  }

  /* TODO if builtin command, execute the command */
  if(strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0){
    exit(0);
  }
  if(strcmp(s->verb->string, "cd") == 0){
    if(s->params){
      changed = SetCurrentDirectory(get_word(s->params));
    }
    if(changed){
      return 0;
    }
    else{
      hOutFile = FileOpen((LPCSTR)get_word(s->out), "w");
      CloseHandle(hOutFile);
      return 0;
    }
  }
  /* TODO if variable assignment, execute the assignment and return
  * the exit status */

  /* TODO if external command:
  *  1. set handles
  *  2. redirect standard input / output / error
  *  3. run command
  *  4. get exit code
  */

  redirrect_command(s, &siStartupInfo, &hInFile, &hOutFile, &hErrFile);
  f_ret = exec_simple_proc(s, hErrFile, sa, siStartupInfo, piProcessInfo); /* TODO replace with actual exit status */
  close_handles(hInFile, hOutFile, hErrFile);
  return f_ret;
}

/**
* Process two commands in parallel, by creating two children.
*/
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
  /* TODO execute cmd1 and cmd2 simultaneously */
  BOOL ret_1, ret_2;
  char* cmd;
  SECURITY_ATTRIBUTES sa_1;
  STARTUPINFO siStartupInfo_1;
  PROCESS_INFORMATION piProcessInfo_1;
  HANDLE hOutFile_1 = INVALID_HANDLE_VALUE;
  HANDLE hInFile_1 = INVALID_HANDLE_VALUE;
  HANDLE hErrFile_1 = INVALID_HANDLE_VALUE;

  SECURITY_ATTRIBUTES sa_2;
  STARTUPINFO siStartupInfo_2;
  PROCESS_INFORMATION piProcessInfo_2;
  HANDLE hOutFile_2 = INVALID_HANDLE_VALUE;
  HANDLE hInFile_2 = INVALID_HANDLE_VALUE;
  HANDLE hErrFile_2 = INVALID_HANDLE_VALUE;
  BOOL changed = FALSE;
  char buffer[100];
  int x;
  ZeroMemory(&sa_1, sizeof(SECURITY_ATTRIBUTES));
  sa_1.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa_1.bInheritHandle = TRUE;

  ZeroMemory(&siStartupInfo_1, sizeof(siStartupInfo_1));
  ZeroMemory(&piProcessInfo_1, sizeof(piProcessInfo_1));

  siStartupInfo_1.cb = sizeof(siStartupInfo_1); 

  ZeroMemory(&sa_2, sizeof(SECURITY_ATTRIBUTES));
  sa_2.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa_2.bInheritHandle = TRUE;

  ZeroMemory(&siStartupInfo_2, sizeof(siStartupInfo_2));
  ZeroMemory(&piProcessInfo_2, sizeof(piProcessInfo_2));

  siStartupInfo_2.cb = sizeof(siStartupInfo_2);

  if(cmd2->up != NULL){
    if(cmd2->up->op != OP_PARALLEL){
      return parse_command(cmd2->up, level, father, (void*)(0)) == 0;
    }
  }

  if(cmd1->scmd){
    redirrect_command(cmd1->scmd, &siStartupInfo_1, &hInFile_1, &hOutFile_1, &hErrFile_1);
    cmd = get_argv(cmd1->scmd);
    ret_1 = CreateProcess(NULL,
      (LPSTR)cmd,
      (LPSECURITY_ATTRIBUTES)&sa_1,
      NULL,
      TRUE,
      NORMAL_PRIORITY_CLASS,
      NULL,
      NULL,
      &siStartupInfo_1,
      &piProcessInfo_1);
    free(cmd);
  }

  if(cmd2->scmd){
    redirrect_command(cmd2->scmd, &siStartupInfo_2, &hInFile_2, &hOutFile_2, &hErrFile_2);
    cmd = get_argv(cmd2->scmd);
    ret_2 = CreateProcess(NULL,
      (LPSTR)cmd,
      (LPSECURITY_ATTRIBUTES)&sa_2,
      NULL,
      TRUE,
      NORMAL_PRIORITY_CLASS,
      NULL,
      NULL,
      &siStartupInfo_2,
      &piProcessInfo_2);
    free(cmd);
  }

  if(cmd1->scmd){
    if(ret_1 == FALSE){
      sprintf(buffer, "%s: No such file or directory\n", cmd);
      WriteFile(hErrFile_1, buffer, strlen(buffer), &x, NULL);
    }
    else{
      WaitForSingleObject(piProcessInfo_1.hProcess, INFINITE);
      GetExitCodeProcess(piProcessInfo_1.hProcess, &ret_1);

      CloseHandle(piProcessInfo_1.hProcess);
      CloseHandle(piProcessInfo_1.hThread);
    }
    close_handles(hInFile_1, hOutFile_1, hErrFile_1);
  }

  if(cmd2->scmd){
    if(ret_2 == FALSE){
      sprintf(buffer, "%s: No such file or directory\n", cmd);
      WriteFile(hErrFile_2, buffer, strlen(buffer), &x, NULL);
    }
    else{
      WaitForSingleObject(piProcessInfo_2.hProcess, INFINITE);
      GetExitCodeProcess(piProcessInfo_2.hProcess, &ret_2);
      CloseHandle(piProcessInfo_2.hProcess);
      CloseHandle(piProcessInfo_2.hThread);
    }
    close_handles(hInFile_2, hOutFile_2, hErrFile_2);
  }
  if(cmd1->scmd && cmd2->scmd){
    return (ret_2 == 0 &&  ret_1 == 0);
  }

  if(!cmd1->scmd){
    do_in_parallel(cmd1->cmd1, cmd1->cmd2, level, cmd1);
  }

  if(!cmd2->scmd){
    do_in_parallel(cmd2->cmd1, cmd2->cmd2, level, cmd2);
  }

  return (ret_1 && ret_2); /* TODO replace with actual exit status */
}

/**
* Run commands by creating an annonymous pipe (cmd1 | cmd2)
*/
static bool do_on_pipe(command_t *s, int level, command_t *father, simple_command_t *queue[100], unsigned int *queue_len)
{  
  SECURITY_ATTRIBUTES sa;
  STARTUPINFO siStartupInfo;
  PROCESS_INFORMATION piProcessInfo;
  HANDLE hOutFile = INVALID_HANDLE_VALUE;
  HANDLE hInFile = INVALID_HANDLE_VALUE;
  HANDLE hErrFile = INVALID_HANDLE_VALUE;
  BOOL changed = FALSE;
  unsigned int i;
  HANDLE fdes[30][2];
  if(!s)
    return true;
  if(s->scmd){
    queue[*queue_len] = s->scmd;
    (*queue_len)++;
    return true;
  }

  if(s->cmd1 != NULL){
    do_on_pipe(s->cmd1, level+1, s, queue, queue_len);
  }

  if(s->cmd2 != NULL){
    do_on_pipe(s->cmd2, level+1, s, queue, queue_len);
  }

  if(s->up == NULL || s->up->op != OP_PIPE){

    //initializare atribute securitate
    ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;

    ZeroMemory(&siStartupInfo, sizeof(siStartupInfo));
    ZeroMemory(&piProcessInfo, sizeof(piProcessInfo));
    siStartupInfo.cb = sizeof(siStartupInfo); 
    //creare n-1 pipe-uri
    for(i = 0; i < (*queue_len) - 1 ; i++){
      changed = CreatePipe(&fdes[i][0], &fdes[i][1], &sa, 11* 1024 *1024);
    }
    redirrect_command(queue[0], &siStartupInfo, &hInFile, &hOutFile, &hErrFile);
    RedirectHandle(&siStartupInfo, fdes[0][1], STD_OUTPUT_HANDLE);
    exec_simple_proc(queue[0], hErrFile, sa, siStartupInfo, piProcessInfo);
    close_handles(hInFile, hOutFile, hErrFile);
    CloseHandle(fdes[0][1]);

    for(i = 1; i < (*queue_len) - 1; ++i){
      redirrect_command(queue[0], &siStartupInfo, &hInFile, &hOutFile, &hErrFile);
      RedirectHandle(&siStartupInfo,  fdes[i][1], STD_OUTPUT_HANDLE);
      RedirectHandle(&siStartupInfo,  fdes[i-1][0], STD_INPUT_HANDLE);
      exec_simple_proc(queue[i], hErrFile, sa, siStartupInfo, piProcessInfo);
      close_handles(hInFile, hOutFile, hErrFile);
      CloseHandle(fdes[i][1]);
      CloseHandle(fdes[i-1][0]);
    }
    redirrect_command(queue[(*queue_len)-1], &siStartupInfo, &hInFile, &hOutFile, &hErrFile);
    RedirectHandle(&siStartupInfo, fdes[(*queue_len)-2][0], STD_INPUT_HANDLE);
    exec_simple_proc(queue[(*queue_len)-1], hErrFile, sa, siStartupInfo, piProcessInfo);
    close_handles(hInFile, hOutFile, hErrFile);
    CloseHandle(fdes[(*queue_len)-2][0]);

  }

  return true; /* TODO replace with actual exit status */
}

/**
* Parse and execute a command.
*/
int parse_command(command_t *c, int level, command_t *father, void *h)
{
  /* TODO sanity checks */

  if (c->op == OP_NONE) {
    /* TODO execute a simple command */

    /* TODO replace with actual exit code of command */
    return parse_simple(c->scmd, level, father, (HANDLE*)h);
  }

  switch (c->op) {
  case OP_SEQUENTIAL:
    /* TODO execute the commands one after the other */
    parse_command(c->cmd1, level+1, c, (HANDLE*)h);
    return parse_command(c->cmd2, level+1, c, (HANDLE*)h);
    break;

  case OP_PARALLEL:
    /* TODO execute the commands simultaneously */
    if(do_in_parallel(c->cmd1, c->cmd2, level, father)){
      return 0;
    }
    return -1;
    break;

  case OP_CONDITIONAL_NZERO:
    /* TODO execute the second command only if the first one
    * returns non zero */
    if(parse_command(c->cmd1, level+1, c, (HANDLE*)h)){
      return parse_command(c->cmd2, level+1, c, (HANDLE*)h);
    }
    break;

  case OP_CONDITIONAL_ZERO:
    /* TODO execute the second command only if the first one
    * returns zero */
    if(parse_command(c->cmd1, level+1, c, (HANDLE*)h) == FALSE){
      return parse_command(c->cmd2, level+1, c, (HANDLE*)h);
    }
    break;

  case OP_PIPE:{
    /* TODO redirect the output of the first command to the
    * input of the second */
    struct simple_command_t *cmds[100];
    unsigned int x = 0;
    if (do_on_pipe(c, level, father, cmds, &x)){
      return 0;
    }
    else{
      return -1;
    }
    break;
               }
  default:
    return SHELL_EXIT;
  }

  return 0; /* TODO replace with actual exit code of command */
}

/**
* Readline from mini-shell.
*/
char *read_line()
{
  char *instr;
  char *chunk;
  char *ret;

  int instr_length;
  int chunk_length;

  int endline = 0;

  chunk = calloc(CHUNK_SIZE, sizeof(char));
  if (chunk == NULL) {
    fprintf(stderr, ERR_ALLOCATION);
    exit(EXIT_FAILURE);
  }

  instr = NULL;
  instr_length = 0;

  while (!endline) {
    ret = fgets(chunk, CHUNK_SIZE, stdin);
    if (ret == NULL) {
      break;
    }

    chunk_length = strlen(chunk);
    if (chunk[chunk_length - 1] == '\n') {
      chunk[chunk_length - 1] = 0;
      endline = 1;
    }

    instr = realloc(instr, instr_length + CHUNK_SIZE);
    if (instr == NULL) {
      free(ret);
      return instr;
    }

    memset(instr + instr_length, 0, CHUNK_SIZE);
    strcat(instr, chunk);
    instr_length += chunk_length;
  }

  free(chunk);

  return instr;
}

