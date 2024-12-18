#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define NAME_MAX_LENGTH 32
#define COMMAND_MAX_LENGTH 64

struct Info {
    char logger[COMMAND_MAX_LENGTH];
    int total_academic_unit;
    float total_gpa;
};

struct Module {
    char name[NAME_MAX_LENGTH];
    int academic_unit;
    float grade_point;
};

struct App {
    struct Module *list;
    struct Module selected;
    struct Info stats;
} app;

char *read_str() {
    char *buffer = malloc(40);
    fflush(stdout);
    read(0, buffer, 40);
    return buffer;
}

int read_int() {
    char *choice = read_str();
    return atoi(choice);
}

float read_float() {
    char *choice = read_str();
    return atof(choice);
}

void select_module() {
    printf("Index (0-9): ");
    int index = read_int();
    if (index < 0) {
        printf("[-] Underloading Detected!!!\n");
        return;
    }
    else if (index > 9) {
        printf("[-] Overloading Detected!!!\n");
        return;
    }

    struct Module *p = &app.list[index];

    strcpy(app.selected.name, p->name);
    app.selected.academic_unit = p->academic_unit;
    app.selected.grade_point = p->grade_point;
}

void sum_academic_unit() {
    int total_academic_unit = 0;
    for (int i=0; i<=9; i++) {
        if (app.list[i].name[0] != '\0') {
            total_academic_unit += app.list[i].academic_unit;
        }
    }
    app.stats.total_academic_unit = total_academic_unit;
}

void calculate_gpa() {
    sum_academic_unit();
    
    float gpa = (app.selected.academic_unit * app.selected.grade_point)/app.stats.total_academic_unit;
    printf("[+] GPA contribution of %s> (%d * %.2f) / %d = %.2f\n", app.selected.name, app.selected.academic_unit, app.selected.grade_point, app.stats.total_academic_unit, gpa);

    app.stats.total_gpa += gpa;
}

void calculate_total_gpa() {
    int total_academic_unit = 0;
    float credited_gpa[10] = {0.00};
    for (int i=0; i<=9; i++) {
        if (app.list[i].name[0] != '\0') {
            total_academic_unit += app.list[i].academic_unit;
            credited_gpa[i] = app.list[i].academic_unit * app.list[i].grade_point;
        }
    }
    app.stats.total_academic_unit = total_academic_unit;
    
    float total_gpa = 0.00;
    for (int i=0; i<=9; i++) {
        total_gpa += credited_gpa[i]/app.stats.total_academic_unit;
    }
    
    app.stats.total_gpa = total_gpa;
}

void add_module() {
    printf("Index (0-9): ");
    int index = read_int();
    if (index < 0) {
        printf("[-] Underloading Detected!!!\n");
        return;
    }
    else if (index > 9) {
        printf("[-] Overloading Detected!!!\n");
        return;
    }
    else if (app.list[index].name[0] != '\0') {
        printf("[-] Index %d is taken by %sPlease delete the module first!\n", index, app.list[index].name);
        return;
    }

    printf("Name: ");
    char *name = read_str();
    strncpy((char *) app.list[index].name, name, NAME_MAX_LENGTH);

    printf("Academic Unit: ");
    app.list[index].academic_unit = read_int();

    printf("Grade Point (A/A+:5.0, A-:4.5 etc.): ");
    app.list[index].grade_point = read_float();
    
    printf("[+] Module Added!\n");
}

void delete_module() {
    printf("Index (0-9): ");
    int index = read_int();
    if (index < 0) {
        printf("[-] Underloading Detected!!!\n");
        return;
    }
    else if (index > 9) {
        printf("[-] Overloading Detected!!!\n");
        return;
    }
    else if (app.list[index].name[0] == '\0') {
        printf("[-] No Module found in Index %d!\n", index);
        return;
    }
    
    memset((char *) app.list[index].name, 0, NAME_MAX_LENGTH);
    app.list[index].academic_unit = 0;
    app.list[index].grade_point = 0.00;
    
    printf("[-] Module Deleted!\n");
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    printf("Welcome to Rookie441's GPA calculator app!!\n");

    printf("\n==================\n");
    printf(" 1) Add Module\n");
    printf(" 2) Delete Module\n");
    printf(" 3) Calculate GPA Contribution\n");
    printf(" 4) Calculate Total GPA\n");

    app.list = (struct Module *) malloc(sizeof(struct Module) * 10);

    strcpy(app.stats.logger, "echo \"-- Total Academic Units: %d, Total GPA: %.2f --\"");
    app.stats.total_gpa = 0.00;
    app.stats.total_academic_unit = 0;

    while(1) {
        printf("\nPlease enter a number (1-4): \n");
        printf("> ");
        int choice = read_int();

        if (choice == 1) {
            add_module();
        }
        else if (choice == 2) {
            delete_module();
        }
        else if (choice == 3) {
            select_module();
            calculate_gpa();
        }
        else if (choice == 4) {
            break;
        }
        else {
            printf("[-] Invalid choice. Please enter a number between 1 and 4.\n");
        }
    }
    
    calculate_total_gpa();
    
    char command[COMMAND_MAX_LENGTH];
    snprintf(command, COMMAND_MAX_LENGTH, app.stats.logger, app.stats.total_academic_unit, app.stats.total_gpa);
    system(command);

    exit(0);
}
