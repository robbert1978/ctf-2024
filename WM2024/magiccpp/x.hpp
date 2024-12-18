#include <iostream>
#include <vector>

struct Book
{
    unsigned long long value;
    char name[24];
    char *context;
};

typedef std::vector<Book> VectorBooks;
std::vector<Book> books;
typedef std::vector<Book>::pointer BookPointer;