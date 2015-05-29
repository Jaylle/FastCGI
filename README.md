# Julia FastCGI Process Manager

Usable, but still in development.

Here's a brief README to get you started.

## Requirements

You'll need to have Julia already compiled somewhere on the system e.g. `/usr/bin/julia`

## Compilation

Compile `main.c` linking `libfcgi` e.g.

```
cc -o bin/julia-fcgi main.c -lfcgi
```

## Running

Just run the binary e.g.

```
./bin/julia-fcgi &
```

(The FPM has recently been reworked to be a stand-alone FastCGI server (whereas it previously relied on spawn-fcgi). It may still be compatible with spawn-fcgi, but I doubt it.)

### Options

The FPM _should_ work out-of-the-box without any options specified (assuming you've followed the above instructions exactly i.e. the FPM binary is in `bin/`)

* `-l [address]` - Address and/or port to listen on e.g. `127.0.0.1:8080` (defaults to `:4545`)
* `-b [path]` - Path to the Julia binary (defaults to `/usr/bin/julia`)
* `-v [path]` - Path to the Julia worker file (defaults to `../julia/worker.jl`)
* `-h [path]` - Path for the HOME environment variable (defaults to `/home`)
* `-s [path]` - Path for a socket used to communicate with Julia workers (defaults to `/var/run/julia_fcgi_server`)
* `-w [number]` - Number of worker processes to spawn (defaults to `1`)

## Connecting

Configure your web server's FastCGI proxy settings as you normally would, using the address and port specified when spawning the FPM e.g. (for nginx)

    location ~ \.jl$ {
        try_files $uri $uri/index.jl =404;

        fastcgi_pass 127.0.0.1:4545;

        fastcgi_param GATEWAY_INTERFACE  CGI/1.1;
        fastcgi_param SERVER_SOFTWARE    nginx;
        fastcgi_param QUERY_STRING       $query_string;
        fastcgi_param REQUEST_METHOD     $request_method;
        fastcgi_param CONTENT_TYPE       $content_type;
        fastcgi_param CONTENT_LENGTH     $content_length;
        fastcgi_param SCRIPT_FILENAME    $document_root$fastcgi_script_name;
        fastcgi_param SCRIPT_NAME        $fastcgi_script_name;
        fastcgi_param REQUEST_URI        $request_uri;
        fastcgi_param DOCUMENT_URI       $document_uri;
        fastcgi_param DOCUMENT_ROOT      $document_root;
        fastcgi_param SERVER_PROTOCOL    $server_protocol;
        fastcgi_param REMOTE_ADDR        $remote_addr;
        fastcgi_param REMOTE_PORT        $remote_port;
        fastcgi_param SERVER_ADDR        $server_addr;
        fastcgi_param SERVER_PORT        $server_port;
        fastcgi_param SERVER_NAME        $server_name;
    }

## Julia pages

Your pages are responsible for outputting the appropriate HTTP headers (mainly just Content-Type) and parsing input. Consider using [this CGI module](https://github.com/Jaylle/CGI.jl) to help.

## Contributing

If you feel like getting involved, here are some ideas for things to look at:

- Sometimes when child processes die, they take other processes in the tree with them. I suspect this may be caused by Julia itself sending a group kill signal (to kill off its own child processes) although you'd have to confirm this yourself. It may also just be that the way my code handles child process exiting is causing the problem.
- `julia_fcgi_worker_dispatch_request` connects to the worker when a request is made; there may be the potential to optimise this by having the connection be opened in advance.
- Recovering from the loss of a worker (e.g. by spawning a replacement) may not be working very well.
- When the FPM forwards the request to a Julia worker, it transfers all the environment variables and POST data over the socket (see `julia_fcgi_worker_dispatch_request`, `julia_fcgi_worker_send_environment` and `julia_fcgi_worker_send_post_data`. I tried in vain to have the Julia worker be able to read directly from envp/STDIN, but couldn't get it to work. However, it may be possible now that I've added the multithreaded FCGX calls and all request data transfers go through the `FCGX_Request` structure). If not, perhaps a more efficient method of IPC can be used and/or the format of the data transfer be optimised.
- As mentioned above, this FPM may no longer be compatible with spawn-fcgi or similar proxies. Perhaps we can add this as an option.
- During some initial benchmarks, this FPM lagged slightly behind PHP and Python. I suspect it may be linked to the two possible optimisations mentioned above, but if you can find some way of confirming this or finding another cause, I will buy you pizza.

[Reading this may also be helpful](https://thenewphalls.wordpress.com/2014/07/11/web-development-in-julia-a-progress-report-warning-contains-benchmarks/)