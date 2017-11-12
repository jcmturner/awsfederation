### Code Flow and Logic
* Call to NewRouter() to get the mux.Router
  * For each API namespace - call addRoutes() method using the get<Namespace>Routes methods to get a map of routes...
    * For each route in the namespaces map of routes...
      * Map provides a handler func
      * Map indicates if the func requires authentication
      * Call WrapCommonHandler()
        * If authentication enabled wrap the namespace's handler func in the AuthnHandler
          * Wrap the handler func in the accessLogger handler
        * Return a handler that first sets standard response headers and then calls the wrapped up handler function's ServeHTTP method
        
        
### Execution Order
The above wrapping results in the following execution order:

| # | Step                                                                                                                    | Handler/Method                                                         | Source File       |
|---|-------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|-------------------|
| 1 | Set the standard response HTTP headers on the responseWriter                                                            | setHeaders                                                             | handler.go        |
| 2 | Get the start time of the operation                                                                                     | accessLogger                                                           | logging.go        |
| 3 | Wrap the responseWriter to be able to get the final HTTP status code returned to the client                             | NewResponseWriterWrapper                                               | responseWriter.go |
| 4 | If authentication is on for the operation on this part of the namespace call the ServeHTTP on the AuthnHandler function | AuthnHandler                                                           | authn.go          |
| 5 | Call the ServeHTTP method of the namespace's handler function                                                           | various from namespace depending on the path and method of the request | various           |
| 6 | Return to the accessLogger function to actually write the log line                                                      | accessLogger                                                           | logging.go        |