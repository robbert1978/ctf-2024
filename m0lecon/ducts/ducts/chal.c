/* This file was generated by the Hex-Rays decompiler version 8.3.0.230608.
   Copyright (c) 2007-2021 Hex-Rays <info@hex-rays.com>

   Detected compiler: GNU C++
*/
#define _GNU_SORUCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef uint32_t uint;
typedef uint32_t _DWORD;
typedef uint16_t _WORD;
#define __int64 long long

typedef struct Msg
{
  uint cmd;
  uint len;
  struct Msg *next;
  char name[64];
  uint64_t hehe;
  char buf[];
} Msg;

typedef struct Cmd
{
  uint mark;
  uint num;
  uint64_t idx;
  uint64_t hehe;
} Cmd;

Msg *first = NULL;
Msg *last = NULL;
Msg *NULL_MESSAGE = NULL;
FILE *devnull;

Msg *create_fill_message(char *name, char *a2, int nReadBytes);
void destroy_packet(void *a1);
ssize_t send_message(Msg *a1, int a2);
uint identify_incoming(int a1);
Cmd *receive_command(int a1);
Msg *receive_message(int a1);

Msg *handle_message(int a1)
{
  Msg *result; // rax
  Msg *v2;     // [rsp+18h] [rbp-8h]

  v2 = receive_message(a1);
  printf("Destroying message with len '%d' by %s\n", v2->len, v2->name);
  fwrite(&v2->hehe, 1uLL, (int)v2->len, devnull);
  if (first == NULL_MESSAGE)
    first = v2;
  else
    last->next = v2;
  result = v2;
  last = v2;
  return result;
}
// 40E8: using guessed type void *NULL_MESSAGE;

//----- (0000000000001530) ----------------------------------------------------
Msg *print_messages()
{
  Msg *result; // rax
  Msg *i;      // [rsp+8h] [rbp-8h]

  for (i = first;; i = i->next)
  {
    result = NULL_MESSAGE;
    if (i == NULL_MESSAGE || !i)
      break;
    printf("Message %p is '%s' by %s. Next is %p\n", i, (const char *)&i->hehe, i->name, i->next);
  }
  return result;
}

//----- (00000000000015A2) ----------------------------------------------------
Msg *flush_messages()
{
  Msg *result; // rax

  first = NULL_MESSAGE;
  result = NULL_MESSAGE;
  last = NULL_MESSAGE;
  return result;
}

//----- (00000000000015C9) ----------------------------------------------------
void redact_message(Cmd *a1)
{
  int v1;  // [rsp+14h] [rbp-14h]
  Msg *v2; // [rsp+18h] [rbp-10h]
  Msg *i;  // [rsp+20h] [rbp-8h]

  v1 = 0;
  v2 = NULL_MESSAGE;
  for (i = first; i != NULL_MESSAGE && v2 == NULL_MESSAGE; i = i->next)
  {
    if (v1 == a1->idx)
      v2 = i;
    ++v1;
  }
  if (v2 != NULL_MESSAGE)
  {
    v2->len = 1;
    v2->hehe = a1->hehe;
  }
}

//----- (0000000000001669) ----------------------------------------------------
void handle_command(int a1)
{
  uint num; // eax
  Cmd *v2;  // [rsp+18h] [rbp-8h]

  v2 = receive_command(a1);
  num = v2->num;
  if (num == 0xDEADC0DE)
  {
    flush_messages();
    goto LABEL_9;
  }
  if ((int)num > (int)0xDEADC0DE)
    goto LABEL_8;
  if (num == 0xCAFEBABE)
  {
    redact_message(v2);
    goto LABEL_9;
  }
  if (num != 0xDEADBEEF)
  {
  LABEL_8:
    printf("Invalid command %d", v2->num);
    goto LABEL_9;
  }
  print_messages();
LABEL_9:
  destroy_packet(v2);
}

//----- (00000000000016FC) ----------------------------------------------------
void backend(int a1)
{
  uint v1; // [rsp+1Ch] [rbp-4h]

  first = NULL_MESSAGE;
  last = NULL_MESSAGE;
  devnull = fopen("/dev/null", "w");
  while (1)
  {
    v1 = identify_incoming(a1);
    if (v1 == 1)
    {
      handle_command((unsigned int)a1);
    }
    else if (!v1)
    {
      handle_message(a1);
    }
  }
}
// 1669: using guessed type __int64  handle_command(_QWORD);

//----- (0000000000001787) ----------------------------------------------------
// bad sp value at call has been detected, the output may be wrong!
void talk(int sockfd, int pipefd)
{
  int v2;            // eax
  int nReadBytes;    // [rsp+10h] [rbp-27168h]
  int j;             // [rsp+14h] [rbp-27164h]
  int i;             // [rsp+18h] [rbp-27160h]
  int v6;            // [rsp+1Ch] [rbp-2715Ch]
  Msg *fill_message; // [rsp+20h] [rbp-27158h]
  char name[64];     // [rsp+28h] [rbp-27150h] BYREF
  char buf[160000];  // [rsp+68h] [rbp-27110h] BYREF

  memset(name, 0, sizeof name);
  memset(buf, 0, sizeof buf);

  nReadBytes = 0;
  dprintf(sockfd, "Welcome to the network blackhole! What do you want to destroy?\n");
  do
  {
    v6 = read(sockfd, &buf[nReadBytes], 0x27100 - nReadBytes);
    for (i = 0; i < v6 && buf[nReadBytes + i] != '\n'; ++i)
      ;
    nReadBytes += i;
  } while (i >= v6);
  buf[nReadBytes] = 0;
  dprintf(sockfd, "Please leave also your name for recording purposes!\n");
  read(sockfd, name, 64uLL);
  for (j = 0; j <= 63 && name[j] != 10; ++j)
    ;
  name[j] = 0;
  fill_message = create_fill_message(name, buf, nReadBytes);
  v2 = rand();
  usleep(1000 * (v2 % 10 + 1));
  send_message(fill_message, pipefd);
  dprintf(sockfd, "Data sent to the blackhole, bye!\n");
  destroy_packet(fill_message);
  close(sockfd);
  exit(0);
}
// 18C6: bad sp value at call
// 1925: bad sp value at call
// 1787: using guessed type char name[64];

//----- (00000000000019C8) ----------------------------------------------------
int main(int argc, const char **argv, const char **envp)
{
  int *v3;              // rax
  uint16_t v4;          // ax
  socklen_t addr_len;   // [rsp+8h] [rbp-48h] BYREF
  socklen_t len;        // [rsp+Ch] [rbp-44h] BYREF
  int fd;               // [rsp+10h] [rbp-40h]
  int v9;               // [rsp+14h] [rbp-3Ch]
  int pipedes[2];       // [rsp+18h] [rbp-38h] BYREF
  struct sockaddr s;    // [rsp+20h] [rbp-30h] BYREF
  struct sockaddr addr; // [rsp+30h] [rbp-20h] BYREF

  alarm(0x3Cu);
  pipe(pipedes);
  if (!fork())
    backend(pipedes[0]);
  fd = socket(2, 1, 0);
  if (fd == -1)
  {
    puts("socket creation failed...");
    exit(1);
  }
  puts("Socket successfully created..");
  memset(&s, 0, sizeof(s));
  s.sa_family = 2;
  *(_DWORD *)&s.sa_data[2] = htonl(0);
  *(_WORD *)s.sa_data = htons(0);
  if (bind(fd, &s, 0x10u))
  {
    puts("socket bind failed...");
    exit(1);
  }
  puts("Socket successfully binded..");
  if (listen(fd, 5))
  {
    puts("Listen failed...");
    exit(1);
  }
  puts("Server listening..");
  len = 16;
  if (getsockname(fd, &s, &len))
  {
    v3 = __h_errno_location();
    printf("failed to get hostname with errno %d\n", (unsigned int)*v3);
    exit(1);
  }
  v4 = htons(*(uint16_t *)s.sa_data);
  printf("Port is %u\n", v4);
  addr_len = 16;
  while (1)
  {
    v9 = accept(fd, &addr, &addr_len);
    if (!v9)
      break;
    if (!fork())
      talk(v9, pipedes[1]);
  }
  close(fd);
  return 0;
}

//----- (0000000000001BDD) ----------------------------------------------------
Msg *create_message(int nReadBytes)
{
  Msg *result; // rax

  result = (Msg *)malloc(nReadBytes + 80LL);
  result->cmd = 0;
  result->next = NULL_MESSAGE;
  result->len = nReadBytes;
  return result;
}
// 40E8: using guessed type void *NULL_MESSAGE;

//----- (0000000000001C2A) ----------------------------------------------------
Msg *create_fill_message(char *name, char *a2, int nReadBytes)
{
  Msg *message; // [rsp+28h] [rbp-8h]

  message = create_message(nReadBytes);
  memcpy(message->name, name, sizeof(message->name));
  memcpy(&message->hehe, a2, nReadBytes);
  return message;
}

//----- (0000000000001C8E) ----------------------------------------------------
Cmd *create_command(int a1)
{
  Cmd *result; // rax

  result = (Cmd *)malloc(0x18uLL);
  result->mark = 1;
  result->num = a1;
  return result;
}

//----- (0000000000001CC5) ----------------------------------------------------
void destroy_packet(void *a1)
{
  free(a1);
}

//----- (0000000000001CE4) ----------------------------------------------------
ssize_t send_message(Msg *a1, int a2)
{
  return write(a2, a1, a1->len + 80);
}

//----- (0000000000001D1D) ----------------------------------------------------
ssize_t send_command(const void *a1, int a2)
{
  return write(a2, a1, 0x18uLL);
}

//----- (0000000000001D50) ----------------------------------------------------
uint identify_incoming(int a1)
{
  uint buf; // [rsp+14h] [rbp-Ch] BYREF
  read(a1, &buf, 4uLL);
  return buf;
}

//----- (0000000000001D9D) ----------------------------------------------------
Msg *receive_message(int a1)
{
  int len_msg;  // [rsp+10h] [rbp-30h] BYREF
  int v3;       // [rsp+14h] [rbp-2Ch]
  void *p_next; // [rsp+18h] [rbp-28h]
  Msg *message; // [rsp+20h] [rbp-20h]
  __int64 len;  // [rsp+28h] [rbp-18h]
  ssize_t v7;   // [rsp+30h] [rbp-10h]

  read(a1, &len_msg, 4uLL);
  message = create_message(len_msg);
  len = len_msg + 0x48LL;
  p_next = &message->next;
  v3 = 0;
  while (len > v3)
  {
    v7 = read(a1, p_next, len - v3);
    if (v7 == -1 || !v7)
    {
      printf("Protocol error!");
      exit(1);
    }
    v3 += v7;
    p_next = (char *)p_next + v7;
  }
  return message;
}

//----- (0000000000001E89) ----------------------------------------------------
Cmd *receive_command(int a1)
{
  int buf;      // [rsp+1Ch] [rbp-14h] BYREF
  Cmd *command; // [rsp+20h] [rbp-10h]

  read(a1, &buf, 4uLL);
  command = create_command(buf);
  read(a1, &command->idx, 0x10uLL);
  return command;
}
