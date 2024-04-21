#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#ifdef _WIN32
#define CLEAR_COMMAND "cls"
#else
#define CLEAR_COMMAND "clear"
#endif

using namespace std;

class TodoApp {
public:
    TodoApp() {
        loadTodoList();
    }

    void run() {
        char choice;
        do {
            displayMenu();
            cin >> choice;
            system(CLEAR_COMMAND); // Clear screen after choice
            switch (choice) {
                case '1':
                    displayTodoList();
                    break;
                case '2':
                    addTodoItem();
                    break;
                case '3':
                    markAsDone();
                    break;
                case '4':
                    saveTodoList();
                    cout << "ToDo List saved successfully." << endl;
                    break;
                case '5':
                    cout << "Exiting ToDo List application." << endl;
                    break;
                default:
                    cout << "Invalid choice. Please try again." << endl;
                    break;
            }
        } while (choice != '5');
    }

private:
    vector<string> todoList;

    void displayMenu() {
        cout << "\nToDo List Menu:" << endl;
        cout << "1. Display ToDo List" << endl;
        cout << "2. Add Todo Item" << endl;
        cout << "3. Mark Todo Item as Done" << endl;
        cout << "4. Save ToDo List" << endl;
        cout << "5. Exit" << endl;
        cout << "Enter your choice: ";
    }

    void displayTodoList() {
        cout << "\nToDo List:" << endl;
        if (todoList.empty()) {
            cout << "No items in the ToDo List." << endl;
        } else {
            for (size_t i = 0; i < todoList.size(); ++i) {
                cout << i + 1 << ". " << todoList[i] << endl;
            }
        }
    }

    void addTodoItem() {
        cout << "Enter the task to add: ";
        string task;
        cin.ignore();
        getline(cin, task);
        todoList.push_back(task);
        system(CLEAR_COMMAND); // Clear screen after adding task
    }

    void markAsDone() {
        displayTodoList();
        cout << "Enter the number of the task to mark as done: ";
        size_t index;
        cin >> index;
        if (index > 0 && index <= todoList.size()) {
            todoList.erase(todoList.begin() + index - 1);
            cout << "Task marked as done." << endl;
        } else {
            cout << "Invalid task number." << endl;
        }
        system(CLEAR_COMMAND); // Clear screen after marking task as done
    }

    void loadTodoList() {
        ifstream file("todo.todo");
        if (file.is_open()) {
            string task;
            while (getline(file, task)) {
                todoList.push_back(task);
            }
            file.close();
        } else {
            cout << "No ToDo List file found. Starting with an empty list." << endl;
        }
    }

    void saveTodoList() {
        ofstream file("todo.todo");
        if (file.is_open()) {
            for (const string &task : todoList) {
                file << task << endl;
            }
            file.close();
        } else {
            cout << "Unable to save ToDo List." << endl;
        }
    }
};

int main() {
    TodoApp todoApp;
    todoApp.run();

    return 0;
}
