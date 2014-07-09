

###
#   > julia_fcgi_worker_instance (type)
#
#       Contains data relevant to this worker instance.
#
#       keep_listening::Bool
#           Flag indicating whether the worker should continue to accept
#           new requests.
#           The worker will shut down once this is set to false.
#       
###

type julia_fcgi_worker_instance
    keep_listening::Bool
    atexit_hook_count::Int32

    julia_fcgi_worker_instance() = new (true, 0)
end

###
#   > julia_fcgi_worker_request (type)
#       
#       Contains data relevant to the received request:
#       
#       worker_instance
#           The current worker instance.
#       server_socket
#           The socket that the FastCGI server is connected on.
#       stdin_read
#           The read end of the emulated STDIN pipe.
#       stdin_write
#           The write end of the emulated STDIN pipe.
###

type julia_fcgi_worker_request
    worker_instance::julia_fcgi_worker_instance
    server_socket
    stdin_read
    stdin_write

    julia_fcgi_worker_request() = new ()
    julia_fcgi_worker_request(worker_instance::julia_fcgi_worker_instance, server_socket) = new (worker_instance, server_socket)
end

##  
#   > julia_fcgi_server_set_env (function)
#
#       Takes an environment variable string in the format
#       of "FIELD=VALUE" and sets the respective value in ENV.
###

function julia_fcgi_server_set_env(variable_raw::String)
    variable = split(variable_raw, '=', 2, true)

    if ((variable_fields = length(variable)) > 0)
        if (variable_fields > 1)
            variable_value = pop!(variable)
        else
            variable_value = ""
        end

        ENV[shift!(variable)] = variable_value
    end
end

###
#   > julia_fcgi_server_get_post_data (function)
#
#       Reads the POST data sent over the socket and forwards to the
#       newly-created STDIN proxy pipe.
###

function julia_fcgi_server_get_post_data(server_socket, stdin_write)
    while true
        # Get byte length of the next message from the socket

        message_length_bytes = readbytes(server_socket, 4)

        # Convert length from byte array to integer

        message_length = parseint(Uint32, bytes2hex(message_length_bytes), 16)

        # Read message / end reading

        if (message_length > 0)
            # There's more data to be read; write to the new STDIN pipe

            message = readbytes(server_socket, message_length)

            write(stdin_write, message)
        else
            # No more data; end of STDIN

            break
        end
    end

    # Close the write end of the STDIN pipe(?)

    close(stdin_write)
end

###
#   > julia_fcgi_server_prepare_request (function)
#
#       Configures the environment for the current request. This involves:
#       - Redirecting STDOUT and STDERR to the socket.
#       - Creating and populating a proxy pipe for STDIN data, from which POST data can be read.
#       - Setting environment variables (containing various CGI values)
#       - Terminating this worker. This command may or may not be sent, at the discretion of the FastCGI server.
###

function julia_fcgi_server_prepare_request(worker_request::julia_fcgi_worker_request)
    # Create a pipe for STDIN (this needs to be done within the loop in case a previous request closed the pipe)

    (worker_request.stdin_read, worker_request.stdin_write) = redirect_stdin()
    redirect_stdin(worker_request.stdin_read)

    # Wait for commands from the FCGI server.

    while true
        command_code = read(worker_request.server_socket, Char)

        if (command_code == 'E')
            # Set an environment variable.

            variable = strip(readline(worker_request.server_socket))

            julia_fcgi_server_set_env(variable)
        elseif (command_code == 'I')
            # Read in POST data.

            julia_fcgi_server_get_post_data(worker_request.server_socket, worker_request.stdin_write)
        elseif (command_code == 'G')
             # "Go" i.e. continue to process request.

            break
        elseif (command_code == 'T')
            # Terminate this worker.

            worker_request.worker_instance.keep_listening = false

            break
        end
    end

    # End of setup.

    return worker_request.worker_instance.keep_listening
end

###
#   > julia_fcgi_server_call_atexit (function)
#
#       Because the server doesn't actually exit, it must call any registered
#       atexit hooks manually. A record is kept in the server instance object
#       of how many atexit hooks were present before the request was dispatched.
#       This way, it knows how many hooks to skip over before it reaches the
#       hooks created by the request.
###

function julia_fcgi_server_call_atexit(worker_request::julia_fcgi_worker_request)
    atexit_hook_limit::Int = (length(Base.atexit_hooks) - worker_request.worker_instance.atexit_hook_count)
    counter::Int = 1

    # If this ever happens, it's probably due to a serious bug or an empty hook stack.

    if (atexit_hook_limit < 1)
        return false
    end

    # Get all hooks up until those registered before the request.

    while (counter <= atexit_hook_limit)
        try
            # Get the next hook and remove it from the stack.

            hook::Function = shift!(Base.atexit_hooks)

            # Call the hook.

            hook()
        catch error
            # Show any errors that may have happened during the hook call.

            write(worker_request.server_socket, "atexit hook error: ")

            Base.showerror(worker_request.server_socket, error, catch_backtrace())
        end

        # Complex arithmetic.

        counter = counter + 1
    end

    # ...

    return true
end

###
#   Program entry point.
###

# Attempt to connect to the registrar's domain socket.

registrar = 0

try
    registrar = connect("/var/run/julia_fcgi_server")
catch error
    exit(-1)
end

# Listen for connections on any available port.

(listen_port, listen_server) = listenany(4545)

### Some cleanup.

atexit(function ()

end)

### Register this worker

# Test for a TA or NRATI response.

response = read(registrar, Char)

if (response == 'T')
    ### TA: The registrar is willing to accept this worker.

    @async begin
        # The first two bytes is the port, in network byte order.

        write(registrar, hton(listen_port))

        # The IP is sent as a newline-terminated string.

        write(registrar, "127.0.0.1\n")

        # ...

        close(registrar)
    end
elseif (response == 'N')
    ### NRATI: The registrar has no place for this worker.

    close(registrar)

    exit(-2)
end

### Start worker server

worker_instance = julia_fcgi_worker_instance()

worker_instance.atexit_hook_count = length(Base.atexit_hooks)

@sync begin
    while (worker_instance.keep_listening)
        server_socket = accept(listen_server)

        @async begin
            # Create a new request object for this request.

            worker_request = julia_fcgi_worker_request(worker_instance, server_socket)

            # Redirect STDOUT and STDERR to the socket

            redirect_stdout(worker_request.server_socket)
            redirect_stderr(worker_request.server_socket)

            # ... 

            try
                # Prepare the environment for this request.

                if (julia_fcgi_server_prepare_request(worker_request))
                    # Change to the directory of the script being executed.

                    cd(dirname(ENV["SCRIPT_FILENAME"]))

                    # Execute the request within a "sandbox" environment process.

                    try
                        evalfile(ENV["SCRIPT_FILENAME"])

                        # ...
                    catch error
                        # Errors are caught and sent to the client, so that the server may live to handle more requests.

                        Base.showerror(worker_request.server_socket, error, catch_backtrace())
                    end
                    
                    # Call atexit hooks.

                    try
                        julia_fcgi_server_call_atexit(worker_request)
                    catch error
                        Base.showerror(worker_request.server_socket, error, catch_backtrace())
                    end

                    # Re-redirect STDOUT and STDERR to the socket - in case the user code directed them elsewhere.

                    redirect_stdout(worker_request.server_socket)
                    redirect_stderr(worker_request.server_socket)
                end
            catch error
                # Errors like this are shown only for debugging purposes.

                write(worker_request.server_socket, "Content-Type: text/html\r\n\r\n")
                write(worker_request.server_socket, "Serious error:<br>\n")
                Base.showerror(worker_request.server_socket, error, catch_backtrace())
            end

            ### Close various handles.

            if (isopen(worker_request.server_socket))
                close(worker_request.server_socket)
            end

            if (isopen(worker_request.stdin_read))
                close(worker_request.stdin_read)
            end

            if (isopen(worker_request.stdin_write))
                close(worker_request.stdin_write)
            end
        end
    end
end
