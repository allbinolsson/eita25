/*
 * Shows user info from local pwfile.
 *  
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)


int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL) {
    printf("Name: %s\n", p->pw_name);
    printf("Passwd: %s\n", p->pw_passwd);
    printf("Uid: %u\n", p->pw_uid);
    printf("Gid: %u\n", p->pw_gid);
    printf("Real name: %s\n", p->pw_gecos);
    printf("Home dir: %s\n",p->pw_dir);
    printf("Shell: %s\n", p->pw_shell);
  } else {
    return NOUSER;
  }
}

/* 
 * Write "login: " and read user input. Copies the username to the
 * username variable.
 */
void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}

void read_password(char *password, char *username) 
{
  char* salt = malloc(2);
  salt[3] = '\0';

  struct pwdb_passwd *p = pwdb_getpwnam(username);
  strncpy(salt, p->pw_passwd, 2);
  printf("Salt: %s\n", salt); // Debugging

  password = crypt(getpass("Password: "), salt);
  printf("Password: %s\n", password); // Debugging

  if (p != NULL) {
    if (strcmp(password, p->pw_passwd) == 0) {
      printf("User authenticated successfully \n");
    } else {
      printf("Unknown user or incorrect password. (password) \n");
    }
  } else {
    printf("Unknown user or incorrect password. (username) \n");
  }
}

int main(int argc, char **argv)
{
  char username[USERNAME_SIZE];
  char password[USERNAME_SIZE];

  while (1) {
    read_username(username);
    read_password(password, username);
  }
}
  

  
