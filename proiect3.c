#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define SNAPSHOT_FILENAME "snapshot.txt"

// Structura pentru a stoca metadatele fiecărei intrări
typedef struct {
    char name[256];
    char type[30]; 
    off_t size;
    time_t modified_time;
} EntryMetadata;

// Funcție pentru a obține metadatele unei intrări (fișier sau director)
void getEntryMetadata(const char *path,EntryMetadata *metadata) {
    //EntryMetadata metadata;
    struct stat fileStat;

    // Obținem informațiile despre fișier/director
    if (stat(path, &fileStat) < 0) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    // Copiem numele și tipul intrării
    strcpy(metadata->name, path);
    if (S_ISDIR(fileStat.st_mode)) {
        strcpy(metadata->type,"Director");
    } else {
        strcpy(metadata->type,"Fisier");
    }
    metadata->size=fileStat.st_size;
    // Copiem timpul ultimei modificări
    metadata->modified_time = fileStat.st_mtime;
}

// Funcție pentru verificarea drepturilor lipsă ale unui fișier și analiza sintactică
void checkPermissionsAndAnalyze(char filepath, const char *isolated_dir, int isSafe, int* countUSF) {
    // Verificăm drepturile de acces ale fișierului
    if (access(filepath, R_OK) == -1 || access(filepath, W_OK) == -1 || access(filepath, X_OK) == -1) {
        // Dacă fișierul are drepturi lipsă, creăm un proces dedicat pentru analiza sintactica
            (*isSafe) = 0;
            (*countUSF)++;
        pid_t pid = fork();
        if (pid < 0) { // Eroare la fork()
            perror("fork");
            exit(EXIT_FAILURE);
        }
        if (pid == 0) { // Proces copil
            // Executăm scriptul de analiză sintactică
            execlp("./verify_for_malicious.sh", "verify_for_malicious.sh", filepath, NULL);
            // Dacă execuția nu reușește, afișăm un mesaj de eroare
            perror("execl");
            exit(EXIT_FAILURE);
        }
         else { // Proces părinte
            // Așteptăm terminarea procesului copil
            int status;
            waitpid(pid, &status, 0);
            // Verificăm dacă procesul copil s-a încheiat cu succes sau nu
            if (WIFEXITED(status)) {
                // Dacă fișierul este considerat periculos, îl izolăm în directorul special
                if (WEXITSTATUS(status) == 1) {
                    char *filename = strrchr(filepath, '/');
                    if (filename == NULL) {
                        filename = filepath; // No directory in path, just the filename
                    } else {
                        filename++; // Move past the last '/'
                    }
                    char newpath[1024];
                    snprintf(newpath, sizeof(newpath), "%s/%s", isolated_dir, filename);
                    printf("\t\t\t\t\t%s-%s\n", newpath, filepath);
                    chmod(newpath, 0777);
                    if (rename(filepath, newpath) != 0) {
                        perror("rename");
                        exit(EXIT_FAILURE);
                    }
                    chmod(newpath, 0000);
                    printf("Fișierul %s a fost izolat în directorul %s\n", filepath, isolated_dir);
                }if(WEXITSTATUS(status) == 2){
                    (*isSafe)=1;
                }
            } else {
                printf("Procesul copil s-a încheiat anormal\n");
            }
        }
    }
}


// Funcție pentru a parcurge directorul și a afișa informații despre fișiere și directoare
void create_snapshot(EntryMetadata *metadata,int *countM,const char *path,const char *isolated_dir,int *countSusF) {
    DIR *dir;
    struct dirent *entry;
    struct stat fileStat;
    int isSafe=1;
    int countUSF=0;

    /*int snapshot_file = open(SNAPSHOT_FILENAME, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (snapshot_file <0) {
        perror("Eroare la crearea snapshot-ului");
        exit(EXIT_FAILURE);
    }*/

    // Deschidem directorul
    if (!(dir = opendir(path))) {
        perror("opendir");
        return;
    }

    // Parcurgem directorul
    while ((entry = readdir(dir)) != NULL) {
        char filepath[1024];
        //strcpy(filepath, path);
        //strcat(filepath, "/");
        //strcat(filepath, entry->d_name);
        isSafe=1;

        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

        // Ignoram intrările curente și părinte din director (".", "..")
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Obținem informații despre fișier/director
        if (stat(filepath, &fileStat) < 0) {
            perror("stat");
            continue;
        }

        //dprintf(snapshot_file,"%s %s %ld bytes\n", (S_ISDIR(fileStat.st_mode)) ? "Directory" : "  File", entry->d_name, fileStat.st_size);
        //printf("%s %s %ld bytes %ld\n", (S_ISDIR(fileStat.st_mode)) ? "Directory" : "  File", entry->d_name, fileStat.st_size,fileStat.st_mtime);

        // Dacă este un director, parcurgem recursiv
        if (S_ISDIR(fileStat.st_mode)) {
            getEntryMetadata(filepath, &metadata[(*countM)++]);
            create_snapshot(metadata,countM,filepath,isolated_dir,countSusF);
        }

        else{
            checkPermissionsAndAnalyze(filepath,isolated_dir,&isSafe,&countUSF);///unsafe file
            if(isSafe==0){
                (*countSusF)++;
                continue;
            }
            else{
            getEntryMetadata(filepath, &metadata[(*countM)++]);
            }
        }
    }

    closedir(dir);
    //close(snapshot_file);
}

void saveVectorMetaFis(EntryMetadata *metadata, const char *director_iesire, char *filepath, int countM) {
    // Check if the output directory exists, create if not
    struct stat st = {0};
    if (stat(director_iesire, &st) == -1) {
        if (mkdir(director_iesire, 0777) == -1) {
            perror("Error creating output directory");
            exit(EXIT_FAILURE);
        }
    }

    // Open the snapshot file for writing
    int snapshot_file = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (snapshot_file < 0) {
        perror("Error opening snapshot file");
        exit(EXIT_FAILURE);
    }

    // Write metadata to the snapshot file
    for (int i = 0; i < countM; i++) {
        if (write(snapshot_file, &metadata[i], sizeof(EntryMetadata)) == -1) {
            perror("Error writing to snapshot file");
            close(snapshot_file);
            exit(EXIT_FAILURE);
        }
    }

    // Close the snapshot file
    if (close(snapshot_file) == -1) {
        perror("Error closing snapshot file");
        exit(EXIT_FAILURE);
    }
}



int main(int argc, char *argv[]) {
    if (argc < 5 || argc >15) {
        printf("eroare nr argumente\n");
        return 1;
    }

    const char *director_iesire=argv[2];
    const char *isolated_dir=argv[4];
    struct stat auxArg; //verificam argumentele
    int nrArgBuneDir=0;
    EntryMetadata met[100];
    int nrProcese=argc-5;
    int pids[nrProcese];
    int argBuneDir[nrProcese];

    for(int i=5;i<argc;i++)
    {
        stat(argv[i],&auxArg); //verific daca e director
        if(!(S_ISDIR(auxArg.st_mode)))
        {
            continue;
        }

        int countM=0;
        char filepath[256];
        nrArgBuneDir++;
        argBuneDir[i-5]=1;

        pid_t pid = fork();
        if (pid == 0) { 
            int countSusF=0;
            printf("Procesul copil cu PID-ul %d a inceput.->%s\n",getpid(),argv[i]);
            create_snapshot(met,&countM,argv[i],isolated_dir,&countSusF);
            snprintf(filepath,sizeof(filepath),"%s/%d.txt",director_iesire,i-5);
            printf("countM=%d in main\n",countM);
            printf("%s\n",filepath);
            saveVectorMetaFis(met,director_iesire,filepath,countM);
            printf("Snapshot creat cu succes.\n");
            exit(0); // Terminăm procesul copil
        } else if (pid < 0) { // Eroare la fork()
            perror("Eroare la fork()");
            exit(EXIT_FAILURE);
        }
        else{
            pids[i-5]=pid;
        }
    }
    printf("\n");

    // Așteptăm terminarea tuturor proceselor copil
    int status;
    int i=0;
    pid_t child_pid;
    while ((child_pid = waitpid(pids[i],&status,0)) > 0) {
        if (WIFEXITED(status)) {
            // Procesul copil s-a terminat normal
            printf("Procesul copil cu PID-ul %d s-a încheiat cu codul %d\n", child_pid, WEXITSTATUS(status));
        } else {
            // Procesul copil s-a terminat anormal
            printf("Procesul copil cu PID-ul %d s-a încheiat anormal\n", child_pid);
        }
        i++;
        sleep(1);
    }

    printf("\n");

    return 0;
}