#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define SNAPSHOT_FILENAME "snapshot.txt"

// Funcție pentru a parcurge directorul și a afișa informații despre fișiere și directoare
void create_snapshot(const char *path) {
    DIR *dir;
    struct dirent *entry;
    struct stat fileStat;

    int snapshot_file = open(SNAPSHOT_FILENAME, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (snapshot_file <0) {
        perror("Eroare la crearea snapshot-ului");
        exit(EXIT_FAILURE);
    }

    // Deschidem directorul
    if (!(dir = opendir(path))) {
        perror("opendir");
        return;
    }

    // Parcurgem directorul
    while ((entry = readdir(dir)) != NULL) {
        char filepath[1024];
        strcpy(filepath, path);
        strcat(filepath, "/");
        strcat(filepath, entry->d_name);

        // Ignoram intrările curente și părinte din director (".", "..")
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Obținem informații despre fișier/director
        if (stat(filepath, &fileStat) < 0) {
            perror("stat");
            continue;
        }

        // Afișăm numele și tipul fișierului/directorului și dimensiunea acestuia
        if(S_ISDIR(fileStat.st_mode))
        {
            dprintf(snapshot_file,"%s %s %ld bytes\n","Directory: " , entry->d_name, fileStat.st_size);

        }
        else 
        {
            dprintf(snapshot_file,"%s %s %ld bytes\n","File: ", entry->d_name, fileStat.st_size);

        }
        //printf("%s %s %ld bytes\n", (S_ISDIR(fileStat.st_mode)) ? "Directory" : "File", entry->d_name, fileStat.st_size);

        // Dacă este un director, parcurgem recursiv
        if (S_ISDIR(fileStat.st_mode)) {
            create_snapshot(filepath);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s error\n", argv[0]);
        return 1;
    }

    for(int i=1;i<argc;i++)
    {
        printf("Snapshot of directory: %s created successfully\n", argv[i]);
        create_snapshot(argv[i]);
    }
    printf("\n");

    // Iterăm prin fiecare director și cream un proces copil pentru fiecare
    for (int i = 1; i < argc; i++) {
        pid_t pid = fork();
        if (pid == 0) { // Proces copil
            create_snapshot(argv[i]);
            exit(0); // Terminăm procesul copil
        } else if (pid < 0) { // Eroare la fork()
            perror("Eroare la fork()");
            exit(EXIT_FAILURE);
        }
    }

    // Așteptăm terminarea tuturor proceselor copil
    int status;
    pid_t child_pid;
    while ((child_pid = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            // Procesul copil s-a terminat normal
            printf("Procesul copil cu PID-ul %d s-a încheiat cu codul %d\n", child_pid, WEXITSTATUS(status));
        } else {
            // Procesul copil s-a terminat anormal
            printf("Procesul copil cu PID-ul %d s-a încheiat anormal\n", child_pid);
        }
    }

    return 0;
}
