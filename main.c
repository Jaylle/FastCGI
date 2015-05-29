#include <errno.h>
#include <fcgi_stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/time.h>

/* */

#define MAX_WORKER_POOL_SIZE 4
#define WORKER_RESPONSE_TIMEOUT 29

/* */

typedef struct {
    unsigned short int exists;
    int worker_owner_number;
    struct sockaddr_in server_address;
} julia_fcgi_worker_info;

/* */

extern char **environ;

/* */

/* Globals */

FCGX_Request julia_fcgx_request;

int julia_fcgx_listen_socket = -1;

char * julia_fcgi_listen_address = NULL;

char * julia_binary_path = NULL;
int julia_binary_path_length;

char * julia_virtual_host_path = NULL;
unsigned short int julia_virtual_host_path_alloc = 0;

char * julia_virtual_host_socket_name = NULL;

char * home_environment_variable = NULL;

int virtual_host_socket = -1;

char * current_exe_directory = NULL;
unsigned int current_exe_directory_length = 0;

struct sockaddr_un julia_virtual_host_address;
socklen_t julia_virtual_host_address_length;

int registrar_server_socket = -1;

long julia_fcgi_target_workers = 1;

int worker_process_ids[MAX_WORKER_POOL_SIZE] = { -1 };

short int next_random_worker = 0;

// Shared pointer to the worker list.

julia_fcgi_worker_info *julia_fcgi_workers;

// 

/****


**/

void julia_fcgi_worker_show_error(char * error_header, char * error_description, short int send_header)
{
    time_t current_time;
    struct tm * current_time_info;
    char current_time_buffer[32];

    // Show headers, if required.

    if (send_header > 0) {
        FCGX_FPrintF(julia_fcgx_request.out, "Content-Type: text/html; charset=utf-8\r\n\r\n");
    }

    // Show error.

    FCGX_FPrintF(julia_fcgx_request.out, 
        "<!DOCTYPE html> \
            <html> \
                <head> \
                    <title>Julia FastCGI server error: %s</title> \
                </head> \
                <body> \
       	            <h1>%s</h1> \
                    <p>%s</p> \
                    <hr> \
                </body> \
            </html>",
        error_header,
        error_header,
        error_description
    );
}

void filerecord(char * string)
{
    FILE * f;

    f = fopen("r", "a+");

    fwrite("\n-------\n", 1, strlen("\n-------\n"), f);
    fwrite(string, 1, strlen(string), f);

    fclose(f);
}

/****

**/

short int julia_fcgi_find_available_worker()
{
    short int worker_index = 0;

    for (worker_index = 0; worker_index < MAX_WORKER_POOL_SIZE; worker_index++) {
        if (julia_fcgi_workers[worker_index].exists == 1 && julia_fcgi_workers[worker_index].worker_owner_number == -1) {
            return worker_index;
        }
    }

    // If we get here, there are no obvious available workers; choose one at 'random'.

    for (worker_index = 0; worker_index < MAX_WORKER_POOL_SIZE; worker_index++) {
        if (++next_random_worker >= MAX_WORKER_POOL_SIZE) {
            next_random_worker = 0;
        }

        if (julia_fcgi_workers[next_random_worker].exists == 1) {
            return next_random_worker;
        }
    }

    // If we get here, the worker pool must be empty.

    return -1;
}

/****

**/

short int julia_fcgi_registrar_find_free_worker_slot()
{
    short int worker_index = 0;

    for (worker_index = 0; worker_index < MAX_WORKER_POOL_SIZE; worker_index++) {
        if (julia_fcgi_workers[worker_index].exists == 0) {
            return worker_index;
        }
    }

    // If we get here, there are no free workers.

    return -1;
}

/****
> julia_fcgi_helper_read_fixed (function)
Fill a buffer until max_length bytes have been read or the socket is closed.
**/

ssize_t julia_fcgi_helper_read_fixed(int socket, char * buffer, size_t bytes_expected, int flags)
{
    size_t bytes_read = 0;
    size_t bytes_read_total = 0;

    while (bytes_read_total < bytes_expected) {
        bytes_read = recv(socket, buffer, (bytes_expected - bytes_read_total), flags);

        if (bytes_read > 0) {
            buffer += bytes_read;

            bytes_read_total += bytes_read;
        }
        else {
            break;
        }
    }

    return bytes_read_total;
}

/****
> julia_fcgi_helper_recv_fixed (function)
Fill a buffer until max_length bytes have been read or the socket is closed.
**/

ssize_t julia_fcgi_helper_read_until(int socket, char * buffer, size_t max_bytes, int flags, char delimiter)
{
    unsigned short int found_delimiter = 0;
    int byte_index = 0;
    size_t bytes_read = 0;
    size_t bytes_read_total = 0;

    while (bytes_read_total < max_bytes) {
        bytes_read = recv(socket, buffer, (max_bytes - bytes_read_total), flags);

        if (bytes_read > 0) {
            bytes_read_total += bytes_read;

            // Look for the delimiter in the message.

            for (byte_index = 0; byte_index < bytes_read; byte_index++) {
                if (buffer[byte_index] == delimiter) {
                    buffer[byte_index] = 0x00;

                    found_delimiter = 1;

                    break;
                }
            }

            if (found_delimiter) {
                break;
            }

            // Advance the buffer.

            buffer += bytes_read;
        }
        else {
            break;
        }
    }

    return bytes_read_total;
}

/****

**/

void julia_fcgi_prepare_virtual_host_socket()
{
    size_t socket_name_length = 0;

    // Set up sockaddr_un structure

    socket_name_length = strlen(julia_virtual_host_socket_name);

    memset(&julia_virtual_host_address, 0x00, sizeof(struct sockaddr_un));

    julia_virtual_host_address.sun_family = AF_UNIX;

    strncpy(julia_virtual_host_address.sun_path, julia_virtual_host_socket_name, 91);

    julia_virtual_host_address.sun_path[socket_name_length] = 0x00;
}

/*
*
*
*/

short int julia_fcgi_virtual_host_connect()
{
    int julia_virtual_host_socket = -1;

    // Create socket

    if ((julia_virtual_host_socket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    // Attempt to connect to virtual host

    if (
        connect(
        julia_virtual_host_socket,
        (struct sockaddr *) &julia_virtual_host_address,
        sizeof(julia_virtual_host_address.sun_family) + strlen(julia_virtual_host_address.sun_path)
        ) != 0
        ) {
        return -2;
    }

    return julia_virtual_host_socket;
}

/*


*/

void julia_virtual_host_send_message(int target_socket, char * message_code, char * message_data)
{
    write(target_socket, message_code, 1);

    if (message_data != NULL) {
        write(target_socket, message_data, strlen(message_data));
        write(target_socket, "\n", 1);
    }
}

/*
*
*
*
*/

void julia_fcgi_create_virtual_host_pool()
{
    
}

/****
julia_fcgi_registrar
Accepts connections from workers and registers them.
**/

short int julia_fcgi_registrar(int registrar_server_socket)
{
    int bytes_read = 0;
    short int worker_index = 0;
    int worker_socket = -1;
    struct sockaddr_un worker_address;
    socklen_t worker_address_length;
    char worker_ip_string[16];

    // Pre-terminate the worker IP buffer (just as a precaution).

    worker_ip_string[sizeof(worker_ip_string)-1] = 0x00;

    // Init worker list.

    for (worker_index = 0; worker_index < MAX_WORKER_POOL_SIZE; worker_index++) {
        julia_fcgi_workers[worker_index].exists = 0;
    }

    // Accept connections.

    while (
        (
            worker_socket = accept(
                registrar_server_socket,
                (struct sockaddr *) &worker_address,
                &worker_address_length
            )
        ) > -1
    ) {
        // Find a free worker node.

        if ((worker_index = julia_fcgi_registrar_find_free_worker_slot()) != -1) {
            julia_fcgi_workers[worker_index].exists = 1;

            // Thank the worker for its participation.

            send(worker_socket, "TA", 2, 0);

            // The first two bytes received will be the port that the worker is listening on.

            julia_fcgi_helper_read_fixed(worker_socket, (char *) &julia_fcgi_workers[worker_index].server_address.sin_port, 2, 0);

            // The remaining bytes will be an IP address in string form, terminated by a newline (0x0A)

            julia_fcgi_helper_read_until(worker_socket, (char *) &worker_ip_string, sizeof(worker_ip_string)-1, 0, 0x0A);

            // Convert the IP from string to network notation.

            julia_fcgi_workers[worker_index].server_address.sin_addr.s_addr = inet_addr(worker_ip_string);

            // Set other values in the worker structure.

            julia_fcgi_workers[worker_index].server_address.sin_family = AF_INET;
            julia_fcgi_workers[worker_index].exists = 1;
            julia_fcgi_workers[worker_index].worker_owner_number = -1;
        } else {
            // Inform the worker that there's no room at the inn.

            send(worker_socket, "NRATI", 5, 0);
        }

        // Close worker socket.

        close(worker_socket);
    }

    // Close the server socket.

    close(registrar_server_socket);

    return 0;
}

/****
> julia_fcgi_setup_registrar (function)
Create a domain socket for workers to register themselves.

Notes:
Would this benefit from a change to UDP?
**/

short int julia_fcgi_setup_registrar()
{
    int child_exit_status = 0;
    size_t socket_name_length = 0;
    struct sockaddr_un registrar_server_address;

    // Remove any existing domain socket (shouldn't exist by this point anyway).

    unlink(julia_virtual_host_socket_name);

    // Set up sockaddr_un structure.
    
    socket_name_length = strlen(julia_virtual_host_socket_name);

    memset(&registrar_server_address, 0x00, sizeof(struct sockaddr_un));

    registrar_server_address.sun_family = AF_UNIX;

    strncpy(registrar_server_address.sun_path, julia_virtual_host_socket_name, 91);

    registrar_server_address.sun_path[socket_name_length] = 0x00;

    // Listen for workers on the domain socket.
    
    if ((registrar_server_socket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    if (
        bind(
        registrar_server_socket,
        (const struct sockaddr *) &registrar_server_address,
        (sizeof(registrar_server_address))
        ) != 0
        ) {
        return -2;
    }

    if (listen(registrar_server_socket, 1) != 0) {
        return -3;
    }

    // Create shared memory for worker list.

    julia_fcgi_workers = mmap(NULL, (sizeof(julia_fcgi_worker_info)* MAX_WORKER_POOL_SIZE), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    // Spawn child process to handle worker connections.

    switch (fork()) {
    case -1:
        // TO DO

        break;

    case 0:
        // Handle connections.

        julia_fcgi_registrar(registrar_server_socket);

        // Quit child process.

        exit(child_exit_status);
    }

    // 

    return 0;
}

/****

**/

short int julia_fcgi_setup(int argc, char * argv[])
{
    int setup_code = 0;

    // Configure the server.

    if ((setup_code = julia_fcgi_setup_config(argc, argv)) < 0) {
        return setup_code;
    }

    // Set up the worker registration server.

    if ((setup_code = julia_fcgi_setup_registrar()) < 0) {
        return setup_code;
    }

    return 0;
}

/*
* julia_fcgi_setup() - Detects config values
*
*/

int julia_fcgi_setup_config(int argc, char * argv[])
{
    int option_flag = 0;
    char current_exe_path[BUFSIZ];

    /* Parse command line options */

    while ((option_flag = getopt(argc, argv, "b:v:h:s:w:p:")) != -1) {
        switch (option_flag) {
            case 'l':
                // Address/port for the FastCGI server to listen on.

                julia_fcgi_listen_address = optarg;
                
                break;
                
            case 'b':
                // Path to Julia binary.

                julia_binary_path = optarg;

                break;

            case 'v':
                // Path to Julia virtual host file (see ./julia/worker.jl)

                julia_virtual_host_path = optarg;

                break;

            case 'h':
                // Path for default HOME environment variable.

                home_environment_variable = optarg;

                break;

            case 's':
                // Path for the server socket.

                julia_virtual_host_socket_name = optarg;

                break;

            case 'w':
                // Number of workers to create.

                julia_fcgi_target_workers = strtol(optarg, NULL, 10);

                if (julia_fcgi_target_workers == 0) {
                    julia_fcgi_target_workers = 1;
                }
                else if (julia_fcgi_target_workers > MAX_WORKER_POOL_SIZE) {
                    julia_fcgi_target_workers = MAX_WORKER_POOL_SIZE;
                }

                break;
        }
    }

    // Get path to julia_fcgi binary directory.

    readlink("/proc/self/exe", current_exe_path, BUFSIZ);

    current_exe_directory = dirname(current_exe_path);

    current_exe_directory_length = strlen(current_exe_directory);

    // Set default port.
    
    if (julia_fcgi_listen_address == NULL) {
        julia_fcgi_listen_address = ":4545";
    }
    
    // Set default path to Julia binary.

    if (julia_binary_path == NULL) {
        julia_binary_path = "/usr/bin/julia";
    }

    // Verify that the specified binary file is present and correct.

    if (access(julia_binary_path, F_OK) != 0) {
        return -1;
    }

    // Save length of binary path.

    julia_binary_path_length = strlen(julia_binary_path);

    /* Configure default HOME value (required by Julia) */

    if (home_environment_variable == NULL) {
        // Try to get HOME from environment.

        home_environment_variable = getenv("HOME");

        if (home_environment_variable == NULL) {
            // Julia requires at least something; this can possibly be handled better, but it'll do for now.

            home_environment_variable = "/home";
        }
    }

    // Set HOME in case it is not already set.

    setenv("HOME", home_environment_variable, 1);

    /* Set default path to Julia virtual host */

    if (julia_virtual_host_path == NULL) {
        julia_virtual_host_path = malloc(current_exe_directory_length + 24);
        julia_virtual_host_path_alloc = 1;

        julia_virtual_host_path[0] = 0x00;

        strcat(julia_virtual_host_path, current_exe_directory);
        strcat(julia_virtual_host_path, "/../julia/worker.jl");
    }

    // Verify that the specified virtual host file is present and correct.

    if (access(julia_virtual_host_path, F_OK) != 0) {
        return -2;
    }
    
    // Set default path to virtual host socket.

    if (julia_virtual_host_socket_name == NULL) {
        julia_virtual_host_socket_name = "/var/run/julia_fcgi_server";
    }

    // 

    return 0;
}

/*

*/

void julia_fcgi_teardown_virtual_host_pool()
{

}

/*
julia_fcgi_cleanup()
Guess.

*/

void julia_fcgi_cleanup()
{
    // If the virtual host path was dynamically created, free the allocated memory.

    if (julia_virtual_host_path_alloc == 1 && julia_virtual_host_path != NULL) {
        free(julia_virtual_host_path);
        julia_virtual_host_path = NULL;
    }

    // Close the registrar socket.

    close(registrar_server_socket);

    // Cleanup domain socket.

    if (julia_virtual_host_socket_name != NULL) {
        unlink(julia_virtual_host_socket_name);
    }

    // Terminate virtual host process, if required.

    julia_fcgi_teardown_virtual_host_pool();
}

/****
> julia_fcgi_worker_send_message (function)
Send a message (with optional data) to the Julia worker
in a format that the worker will understand.
**/

void julia_fcgi_worker_send_message(int worker_socket, char * message_code, char * message_data)
{
    send(worker_socket, message_code, 1, 0);

    if (message_data != NULL) {
        send(worker_socket, message_data, strlen(message_data), 0);
        send(worker_socket, "\n", 1, 0);
    }
}

/****
> julia_fcgi_worker_send_environment (function)
Send the current environment variables to the worker.
**/

void julia_fcgi_worker_send_environment(int worker_socket)
{
    int environment_index = 0;

    while (julia_fcgx_request.envp[environment_index] != NULL) {
        julia_fcgi_worker_send_message(worker_socket, "E", julia_fcgx_request.envp[environment_index++]);
    }
}

/****
> julia_fcgi_worker_send_post_data (function)
Send any POST data to the worker.
**/

void julia_fcgi_worker_send_post_data(int worker_socket)
{
    int bytes_read = 0;
    uint32_t bytes_read_network = 0;
    char buffer[2048];

    // Send the "I" command to inform the worker that POST data is incoming.

    julia_fcgi_worker_send_message(worker_socket, "I", NULL);

    /*
    Read from STDIN and forward to the socket.

    First, a length indicator is sent with the # of the expected bytes.
    The server knows to stop waiting for input when the length message is 0.

    */

    while ((bytes_read = fread(buffer, 1, sizeof(buffer)-1, FCGI_stdin)) > 0) {
        buffer[bytes_read] = 0x00;

        bytes_read_network = htonl(bytes_read);

        send(worker_socket, (char *) &bytes_read_network, sizeof(bytes_read_network), 0);

        send(worker_socket, buffer, bytes_read, 0);
    }

    // Send the "terminator" message (length = 0)

    bytes_read_network = htonl(0);

    send(worker_socket, (char *) &bytes_read_network, sizeof(bytes_read_network), 0);
}

/****
> julia_fcgi_worker_read_response (function)
Read the output sent by the Julia worker and send it to the client (e.g. browser).

Some timeout logic is also tied into this. A worker is given only
WORKER_RESPONSE_TIMEOUT seconds to respond and close the connection before the
controller will initiate killing and restarting the Julia process.
**/

short int julia_fcgi_worker_read_response(int worker_socket)
{
    int bytes_read = 0;
    char buffer[2048];
    struct timeval recv_timeout;
    struct timeval response_start_time;
    struct timeval response_new_time;

    // Get the current time - roughly the time that the request was initiated.

    gettimeofday(&response_start_time, NULL);

    // Set a timeout of 1 second per read attempt.

    recv_timeout.tv_sec = 1;
    recv_timeout.tv_usec = 0;

    setsockopt(worker_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &recv_timeout, sizeof(recv_timeout));

    // Read the output.

    do {
        bytes_read = recv(worker_socket, &buffer, sizeof(buffer)-1, 0);

        if (bytes_read > 0) {
            buffer[bytes_read] = 0x00;
            
            // Write to the FCGI request's output stream.
            
            FCGX_PutStr((const char *) &buffer, bytes_read, julia_fcgx_request.out);
        }

        // Check whether the worker has reached its time limit.

        gettimeofday(&response_new_time, NULL);

        if ((response_new_time.tv_sec - response_start_time.tv_sec) > WORKER_RESPONSE_TIMEOUT) {
            return -1;
        }

        // If 0 bytes were read and errno is neither EAGAIN nor EWOULDBLOCK, there's no more data to receive.

        if (
            bytes_read == 0
            //| (errno != EAGAIN && errno != EWOULDBLOCK)
            ) {
            break;
        }
    } while (1);
    
    return 0;
}

/****
> julia_fcgi_worker_dispatch_request (function)
Connect to the specified Julia worker and process the request.
**/

short int julia_fcgi_worker_dispatch_request(short int worker_index)
{
    int worker_socket = -1;

    // Attempt to connect to the Julia worker.

    if ((worker_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        return -1;
    }

    if (
        connect(
            worker_socket,
            (struct sockaddr *) &julia_fcgi_workers[worker_index].server_address,
            sizeof(julia_fcgi_workers[worker_index].server_address)
        ) < 0
    ) {
        return -2;
    }
    
    // Send environment variables

    julia_fcgi_worker_send_environment(worker_socket);

    // Send input from STDIN.

    julia_fcgi_worker_send_post_data(worker_socket);

    // Send "G" (go) command i.e. no more data to send; continue to process the request.

    julia_fcgi_worker_send_message(worker_socket, "G", NULL);

    // Read response from worker and forward to client.

    if (julia_fcgi_worker_read_response(worker_socket) < 0) {
        // The request has timed out.

        julia_fcgi_worker_show_error(
            "Julia timeout error",
            "This error usually occurs as a result of the worker taking too long to respond or close the connection.",
            1
        );

        // TO DO: Handle this properly.
    }
    
    // Close the connection.

    close(worker_socket);

    return 0;
}

/****
> julia_fcgi_no_workers_available (function)
Called when there are no workers available to handle a request.
**/

void julia_fcgi_no_workers_available(short int worker_number)
{
    julia_fcgi_worker_show_error(
        "Julia worker pool error",
        "This error usually occurs as a result of the FastCGI server's worker pool being empty.",
        1
    );
}

/* */

short int julia_fcgx_server_startup()
{
    // The ..
    
    FCGX_Init();
    
    // Create the listening socket.
    
    julia_fcgx_listen_socket = FCGX_OpenSocket(julia_fcgi_listen_address, 255);
    
    if (julia_fcgx_listen_socket < 0) {
        return -1;
    }
    
    return 1;
}

/****
> julia_fcgi_setup_worker (function)
Configure the worker process.

Each worker has two parts:
1) The "babysitter" within the context of the FastCGI server
2) The Julia process (exec'd)
**/

void julia_fcgi_setup_worker(short int worker_number)
{
    int child_exit_status = 0;
    int worker_index = 0;
    int a = 0, b = 0, c = 0;

    // Divide the worker into 1 controller and 1 Julia process.

    switch (fork()) {
        case -1:
            // TO DO

            break;

        case 0:
            // Child process morphs into a Julia process.

            execle(julia_binary_path, julia_binary_path, julia_virtual_host_path, julia_virtual_host_socket_name, (char *) 0, environ);

            // exec failed; return control to parent process.

            exit(child_exit_status);
    }
    
    // Configure this FastCGI thread.
    
    FCGX_InitRequest(&julia_fcgx_request, julia_fcgx_listen_socket, 0);

    // Controller now accepts FastCGI connections.

    while (FCGX_Accept_r(&julia_fcgx_request) >= 0) {
        // Try to find an available worker.

        if ((worker_index = julia_fcgi_find_available_worker()) != -1) {
            // If the worker isn't owned by another controller, advise future requests that it's in use by the current controller.

            if (julia_fcgi_workers[worker_index].worker_owner_number == -1) {
                julia_fcgi_workers[worker_index].worker_owner_number = worker_number;
            }
            
            // Dispatch the request to the Julia worker.

            switch (julia_fcgi_worker_dispatch_request(worker_index)) {
                case -1:
                    // Socket error. This should never happen, but it's handled here anyway.

                    julia_fcgi_worker_show_error(
                        "Julia worker socket error",
                        "This error usually occurs as a result of the FastCGI server being unable to create a socket.",
                        1
                    );

                    break;
                    
                case -2:
                    // Connection error. This happens if there's a problem with the Julia worker.

                    // TO DO: Trigger recovery of Julia worker process.

                    julia_fcgi_worker_show_error(
                        "Julia worker connection error",
                        "This error usually occurs as a result of the FastCGI server being unable to connect to a Julia worker process.",
                        1
                    );

                    break;
            }

            // If the worker is owned by this controller, advise that the worker is free.

            if (julia_fcgi_workers[worker_index].worker_owner_number == worker_number) {
                julia_fcgi_workers[worker_index].worker_owner_number = -1;
            }
        } else {
            // The pool is empty; handle it.

            julia_fcgi_no_workers_available(worker_number);
        }

        FCGX_Finish_r(&julia_fcgx_request);

        continue;
    }
}

/****
> julia_fcgi_create_worker (function)
Create a single worker process.
**/

void julia_fcgi_create_worker(short int worker_number)
{
    int child_exit_status = 0;

    // Spawn a new worker process.

    switch (worker_process_ids[worker_number] = fork()) {
        case -1:
            // TO DO

            break;

        case 0:
            julia_fcgi_setup_worker(worker_number);

            // exec failed; return control to parent process.

            exit(child_exit_status);
    }
}

/****
> julia_fcgi_create_worker_pool (function)
Populate the worker pool.

**/

void julia_fcgi_create_worker_pool()
{
    short int worker_number = 0;

    for (worker_number = 0; worker_number < julia_fcgi_target_workers; worker_number++) {
        julia_fcgi_create_worker(worker_number);
    }
}

/****
main
Program entry point.
**/

int main(int argc, char * argv[])
{
    int setup_code = 0;
    char * request_file_path = NULL;
    int worker_status = 0;

    // Run setup.

    if ((setup_code = julia_fcgi_setup(argc, argv)) < 0) {
        julia_fcgi_cleanup();

        return setup_code;
    }
    
    // Start FCGI server.
    
    if ((setup_code = julia_fcgx_server_startup()) < 0) {
        julia_fcgi_cleanup();
        
        return setup_code;
    }

    // Spawn workers

    julia_fcgi_create_worker_pool();

    // Wait for workers to quit.

    waitpid(worker_process_ids[0], &worker_status, 0);

    // Clean up and exit.

    julia_fcgi_cleanup();

    return 0;
}