#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>

#define SNAPSHOT_FILENAME "snapshot.txt"

// Funcție pentru a parcurge directorul și a afișa informații despre fișiere și directoare
void listFiles(const char *path) {
    DIR *dir;
    struct dirent *entry;
    struct stat fileStat;

    FILE *snapshot_file = fopen(SNAPSHOT_FILENAME, "w");
    if (snapshot_file == NULL) {
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
        fprintf(snapshot_file,"%s %s %ld bytes\n", (S_ISDIR(fileStat.st_mode)) ? "Directory" : "File", entry->d_name, fileStat.st_size);
        printf("%s %s %ld bytes\n", (S_ISDIR(fileStat.st_mode)) ? "Directory" : "File", entry->d_name, fileStat.st_size);

        // Dacă este un director, parcurgem recursiv
        if (S_ISDIR(fileStat.st_mode)) {
            listFiles(filepath);
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
        printf("Snapshot of directory: %s\n", argv[i]);
        listFiles(argv[i]);
    }

    return 0;
}