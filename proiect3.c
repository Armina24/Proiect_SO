#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

#define SNAPSHOT_DIR "Snapshots"
#define MAX_PATH_LENGTH 1024
#define MAX_FILES 10

// Structura pentru a stoca metadatele fiecărei intrări
typedef struct {
    char name[256];
    char type; // 'D' pentru director, 'F' pentru fișier
    time_t modified_time;
} EntryMetadata;

// Structura pentru a stoca informatii despre un proces copil
typedef struct {
    pid_t pid;
    int num_files;
}ChildProcessInfo;

// Funcție pentru a obține metadatele unei intrări (fișier sau director)
EntryMetadata getEntryMetadata(const char *path) {
    EntryMetadata metadata;
    struct stat fileStat;

    // Obținem informațiile despre fișier/director
    if (stat(path, &fileStat) < 0) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    // Copiem numele și tipul intrării
    strcpy(metadata.name, path);
    if (S_ISDIR(fileStat.st_mode)) {
        metadata.type = 'D';
    } else {
        metadata.type = 'F';
    }

    // Copiem timpul ultimei modificări
    metadata.modified_time = fileStat.st_mtime;

    return metadata;
}

// Funcție pentru a actualiza snapshot-ul pentru un director specificat
void updateSnapshot(const char *directory, const char *output_dir) {
    char snapshot_filename[1024];
    snprintf(snapshot_filename, sizeof(snapshot_filename), "%s/%s/Snapshot.txt", output_dir, SNAPSHOT_DIR);
    
    int snapshot_file = open(snapshot_filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (snapshot_file < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Deschidem directorul
    DIR *dir = opendir(directory);
    if (dir == NULL) {
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    // Iterăm prin fiecare intrare din director și subdirectoare
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignorăm intrările curentă și părinte
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construim calea absolută către intrare
        char entry_path[1024];
        snprintf(entry_path, sizeof(entry_path), "%s/%s", directory, entry->d_name);

        // Obținem metadatele intrării
        EntryMetadata metadata = getEntryMetadata(entry_path);

        // Scriem metadatele în fișierul de snapshot
        dprintf(snapshot_file, "%c %s %ld\n", metadata.type, metadata.name, metadata.modified_time);
    }

    closedir(dir);
    close(snapshot_file);
}

// Functie pentru verificarea drepturilor lipsa ale unui fisier

int hasMissingPermissions(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if ((st.st_mode & S_IRUSR) && (st.st_mode & S_IWUSR) && (st.st_mode & S_IXUSR) &&
            (st.st_mode & S_IRGRP) && (st.st_mode & S_IXGRP) &&
            (st.st_mode & S_IROTH) && (st.st_mode & S_IXOTH)) {
            return 0; // Nu sunt drepturi lipsa
        } else {
            return 1; // Sunt drepturi lipsa
        }
    }
    return -1; // Eroare la obtinerea informatiilor despre fisier
}

// Functie pentru a executa scriptul de verificare a fisierului pentru maleficenta
void executeMaliciousCheckScript(const char *filename, const char *isolated_space_dir,int pipe_fd) {
    char command[2 * MAX_PATH_LENGTH + 100];
    snprintf(command, sizeof(command), "./verify_for_malicious.sh %s %s", filename, isolated_space_dir);
    system(command);
}

// Functie pentru mutarea unui fisier in directorul de izolare
void moveFileToIsolatedSpace(const char *filename, const char *isolated_space_dir) {
    char new_path[MAX_PATH_LENGTH];
    snprintf(new_path, sizeof(new_path), "%s/%s", isolated_space_dir, filename);
    rename(filename, new_path);
}


int main(int argc, char *argv[]) {
   if (argc < 3) {
        printf("Usage: %s -o <output_directory> <directory1> [<directory2> ...]\n", argv[0]);
        return 1;
    }

    char *output_dir = NULL;
    int index;
    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "-o") == 0) {
            if (index + 1 < argc) {
                output_dir = argv[index + 1];
                index++; // Avansăm pentru a omite și directorul de ieșire din lista de argumente
            } else {
                printf("Missing output directory.\n");
                return 1;
            }
        } else {
            break;
        }
    }

    if (output_dir == NULL) {
        printf("Missing output directory.\n");
        return 1;
    }

    // Creăm directorul pentru snapshot-uri dacă nu există
    char snapshot_dir[1024];
    snprintf(snapshot_dir, sizeof(snapshot_dir), "%s/%s", output_dir, SNAPSHOT_DIR);
    mkdir(snapshot_dir, 0755);

    // Actualizăm snapshot-urile pentru fiecare director specificat utilizând procese separate
    for (; index < argc; index++) {
        pid_t pid = fork();
        if (pid == 0) { // Proces copil
            updateSnapshot(argv[index], output_dir);
            printf("Snapshot for Directory %s created successfully.\n", argv[index]);
            exit(0); // Terminăm procesul copil
        } else if (pid < 0) { // Eroare la fork()
            perror("fork");
            exit(EXIT_FAILURE);
        }
    }

    // Așteptăm terminarea tuturor proceselor copil
    int status;
    pid_t child_pid;
    while ((child_pid = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            // Procesul copil s-a terminat normal
            printf("Child Process terminated with PID %d and exit code %d.\n", child_pid, WEXITSTATUS(status));
        } else {
            // Procesul copil s-a terminat anormal
            printf("Child Process terminated abnormally with PID %d.\n", child_pid);
        }
    }

    //cerinta 9
    if (argc < 5) {
        printf("Usage: %s -o <output_directory> <isolated_space_dir> <dir1> [<dir2> ...]\n", argv[0]);
        return 1;
    }

    char *output_dir = NULL;
    char *isolated_space_dir = NULL;

    // Parsare argumente pentru directorul de iesire si directorul de izolare
    for (int i = 1; i < argc - 3; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            output_dir = argv[i + 1];
            i++;
        } else {
            isolated_space_dir = argv[i];
        }
    }

    if (output_dir == NULL || isolated_space_dir == NULL) {
        printf("Invalid arguments.\n");
        return 1;
    }

    // Cream directorul de iesire daca nu exista
    mkdir(output_dir, 0755);

    // Iterare prin toate directoarele date ca argumente
    for (int i = argc - 3; i < argc; i++) {
        DIR *dir = opendir(argv[i]);
        if (dir == NULL) {
            printf("Error: Could not open directory %s\n", argv[i]);
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            // Construirea caii complete catre fisier
            char filepath[MAX_PATH_LENGTH];
            snprintf(filepath, sizeof(filepath), "%s/%s", argv[i], entry->d_name);

            // Verificam daca fisierul are toate drepturile lipsa
            if (hasMissingPermissions(filepath)) {
                // Cream un proces copil pentru fiecare fisier identificat ca avand drepturi lipsa
                pid_t pid = fork();
                if (pid == 0) { // Proces copil
                    executeMaliciousCheckScript(filepath, isolated_space_dir);
                    exit(0);
                } else if (pid < 0) { // Eroare la fork()
                    printf("Error: Failed to fork process for file %s\n", entry->d_name);
                } else { // Proces parinte
                    int status;
                    waitpid(pid, &status, 0); // Asteptam terminarea procesului copil

                    // Verificam daca procesul copil s-a incheiat cu succes
                    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                        moveFileToIsolatedSpace(filepath, isolated_space_dir);
                        printf("File %s moved to isolated space.\n", entry->d_name);
                    } else {
                        printf("Error: Malicious check failed for file %s\n", entry->d_name);
                    }
                }
            }
        }

        closedir(dir);
    }

    //cerinta 10
    // Verificăm argumentele de intrare
    if (argc < 5 || argc > MAX_FILES + 4) {
        printf("Usage: %s -o <output_directory> <isolated_space_dir> <dir1> [<dir2> ...]\n", argv[0]);
        return 1;
    }

    // Parsăm argumentele pentru directorul de ieșire și directorul de izolare
    char *output_dir = NULL;
    char *isolated_space_dir = NULL;
    for (int i = 1; i < argc - 3; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            output_dir = argv[i + 1];
            i++;
        } else {
            isolated_space_dir = argv[i];
        }
    }

    if (output_dir == NULL || isolated_space_dir == NULL) {
        printf("Invalid arguments.\n");
        return 1;
    }

    // Cream directorul de ieșire dacă nu există
    mkdir(output_dir, 0755);

    // Array pentru a stoca informațiile despre procesele copil
    ChildProcessInfo child_processes[MAX_FILES];

    // Iterăm prin toate directoarele date ca argumente
    int num_files = 0;
    for (int i = argc - 3; i < argc; i++) {
        DIR *dir = opendir(argv[i]);
        if (dir == NULL) {
            printf("Error: Could not open directory %s\n", argv[i]);
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            // Construirea căii complete către fișier
            char filepath[MAX_PATH_LENGTH];
            snprintf(filepath, sizeof(filepath), "%s/%s", argv[i], entry->d_name);

            // Verificăm dacă fișierul are toate drepturile lipsă
            if (hasMissingPermissions(filepath)) {
                // Cream un pipe pentru a comunica între procesul părinte și procesul fiu
                int pipe_fd[2];
                if (pipe(pipe_fd) == -1) {
                    perror("pipe");
                    return 1;
                }

                // Cream un proces fiu pentru fiecare fișier identificat ca având drepturi lipsă
                pid_t pid = fork();
                if (pid == 0) { // Proces fiu
                    // Închidem capătul de citire al pipe-ului
                    close(pipe_fd[0]);

                    // Executăm script-ul de verificare a fisierului
                    executeMaliciousCheckScript(filepath, isolated_space_dir, pipe_fd[1]);

                    // Închidem capătul de scriere al pipe-ului și ieșim din procesul fiu
                    close(pipe_fd[1]);
                    exit(0);
                } else if (pid < 0) { // Eroare la fork()
                    perror("fork");
                    return 1;
                } else { // Proces părinte
                    // Închidem capătul de scriere al pipe-ului în procesul părinte
                    close(pipe_fd[1]);

                    // Salvăm informațiile despre procesul fiu în array
                    child_processes[num_files].pid = pid;
                    child_processes[num_files].num_files = 0;

                    // Citim din pipe mesajul transmis de procesul fiu
                    char buffer[256];
                    int bytes_read = read(pipe_fd[0], buffer, sizeof(buffer));
                    if (bytes_read > 0) {
                        // Verificăm dacă mesajul este numele fișierului periculos
                        if (strcmp(buffer, "SAFE") != 0) {
                            printf("File %s moved to isolated space.\n", entry->d_name);
                            moveFileToIsolatedSpace(filepath, isolated_space_dir);
                            child_processes[num_files].num_files = 1;
                        }
                    }

                    // Închidem capătul de citire al pipe-ului
                    close(pipe_fd[0]);

                    // Incrementăm numărul de fișiere
                    num_files++;
                }
            }
        }

        closedir(dir);
    }

    // Așteptăm terminarea tuturor proceselor copil și afișăm mesajele corespunzătoare
    for (int i = 0; i < num_files; i++) {
        int status;
        waitpid(child_processes[i].pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("Child Process %d terminated with PID %d and exit code %d", i + 1, child_processes[i].pid, WEXITSTATUS(status));
            if (child_processes[i].num_files == 0) {
                printf(" and 0 files with potential peril.\n");
            } else {
                printf(" and %d files with potential peril.\n", child_processes[i].num_files);
            }
        } else {
            printf("Child Process %d terminated abnormally with PID %d.\n", i + 1, child_processes[i].pid);
        }
    }

    return 0;
}
