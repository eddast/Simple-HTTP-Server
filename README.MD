# Computer Networks: Programming Assignment III
#### By Arnar Freyr Sævarsson and Edda Steinunn Rúnarsdóttir <br/> <br/> <br/>


## Introduction

A simple **Hypertext Transfer Protocol** (HTTP) server was implemented in C programming language using socket API.
The server listens on two server-specified ports, one for HTTP communication and another for HTTPS (encrypted) communication. It can handle GET, HEAD and POST requests in a specified manner both on a regular HTTP connection and on a secure HTTPS connection. For some request paths such as _color_, _login_ and _secret_ server provides special behaviour described in _Implementation_ section below, while other paths get default response, also described in _Implementation_ section. Implementation and testing of the server took approximately 35-40 hours and code compiles without memory errors or warnings. 


## Structure Explained

Entire implementation is in the file _/src/httpd.c_ and is structured with functions.
A _Transmission Control Protocol_ (TCP) socket API is used in implementation as specified for HTTP protocols.
File has commented header with assignment information and authors.
File is structually divided into sections, each preceded by a commented header: <br/>

* **Functions and constant declarations**. Declarations include comments that define purpose for each declaration
* **Main function**. Contains all functionality executed by program.
* **Functions implementations**. Contain all logic for resolving requests.

Socket initializing, optimization and binding is located in the main function and
is executed first along with initialization of a poll structure, enabling parallel connections.
 Request are recieved while iterating through active connections,
initiating another one if request from a new client is received.
A recursive descent parser structure containing various helper functions is used to handle incoming requests from clients. After execution of this function, the main function sends back a respons
## Implementation Explained

Note that this section covers mostly functionalities and implementation added for **Hypertext Transfer Protocol Server Part II** (Programming Assignment III). Previous implementation for Programming Assignment II is not covered as the _README.MD_ file of that assignment provides explaination of previous implementation.

* ### What the Server Serves
Our server responds with HTTP responses. Each response begins with a status line containing echoed HTTP version specified by client (unless it is an invalid version or a future HTTP version; then HTTP/1.1 is used as default), the client-specified URI and a status code with corresponding reason phrase determining if request was handled successfully. </br>

Our server serves GET, HEAD and POST requests from clients. The default behaviour of our server yields responses in the following formats given different requests:

   * A successful **GET** request has a status code 200 (OK) and yields a response with minimal header fields; they determine Content-Type, Content-Length and Connection (either persistent or non-persistent) to facilitate client to resolve the response. The response's content body will be a HTML page from memory showing URL requested by client (including the URI), client IP address and client port. Then lists query parameters of URI in an unordered list below all this.

* A successful **HEAD** request has a status code 200 (OK) and displays the header fields of a GET request (described above).
   * A successful **POST** request has a status code 201 (CREATED) and displays the same header fields as a GET request but the response's content body will be a HTML page from memory showing URL requested by client (including the URI), client IP address, client port, query parameters of URI in an unordered list and whatever client specified as a post body appended to that.
   * Any other type of request method or an error in parsing request means that the response message will be an error response. Such responses contain the header fields Content-Type, Content-Length and Connection non-persistent header fields and contain a content body with an HTML page displaying the relevant error message to client.

However, three special cases exist which make our server behave slightly differently than the default behavior:

* **Special Case 1: color path requests**: When client correctly sends GET request to our server with the path _color_, the server responds with an empty HMTL page with background color either as specified in query parameter of URI (bg = _COLOR VALUE_) or as specified via color cookie that server sets for client upon each color path request with background color query parameter provided (cookies explained futher in _Cookies_ section below). If neither cookie nor appropriate query parameter exists, white is set as background color. Similarly as the default behaviour HEAD returns header fields for the body which in this case is empty with a specified background color, and POST returns body with specified background color and whatever client provided as a post body. 
* **Special Case 2: login path requests**: When client correctly sends requests to our server with the path _login_, the server needs to authenticate client and sends the WWW Authenticate header to provide a login window to authenticate themselves (authentication process is explained in _Authentication_ section below). Whenever authentication for user is successful request is processed normally. When authentication for user fails, the client receives a 401 UNAUTHORIZED response and may attempt to log in again.

* **Special Case 3: secret path requests**: When client correctly sends requests to our server with the path _secret_, the server checks whether user is authorized but unlike _login_ path requests, does not offer user to log in if authentication fails. Therefore on _secret_ path requests, requests are processed normally if authentication is successful for user, otherwise client receives a 401 UNAUTHORIZED response with appropriate error message as body.

* **Special Case 4: favicon.ico path requests**: As in part one of this assignment, whenever client requests a _favicon.ico_ path requests, server responds with a 404 NOT FOUND response. This implementation specification was suggested by teacher and avoids any confusion.<br/>

Any request, valid or invalid, is logged and stored in the log file _HTTPlog.log_ as well as authorization attempts from client which is created in current directory from where server is run. 

* ### Dictionary
An important feature added for this part of the assignment was a dictionary structure. The structure stores a pair of gchar*, one as a key and one as value associated with key. The dictionary structure has the operations _insert_, _search_ as well as _deallocate_ so that it deallocates each key-value pairs after use. Three dictionaries were used; one for request header fields, one for query parameters of URI and one for cookies (even though only one cookie was set for client for a more generalized code). This faciliated parsing of requests greatly and cleaned up code.

* ### Cookies
Whenever client requests for a path _color_ and provides a query parameter for bg (background color) a cookie called _color_ is set for client and stores client's background color preference. Client then stores the color cookie sent as a header field whenever client sends a request to client which server parses and uses as background color if no background color query parameter is provided in URI.

* ### SSL Connections
As previously stated, the second port whose number is provided as second argument when running server is used for encrypted communication and this feature was added for this part of the assignment. Port is secured via SSL using a self signed certificate located in root directory. The server loads the SSL certificate for port and uses this to encrypt communication between server and client. **PLEASE NOTE** that the client may have to install the certificate as a trusted certificate in order to accept it.



## Server Security Explained

* ### Authentication
Two special cases were mentioned in section _What the Server Serves_ that depend on user authentication, namely requests for _login_ path and requests for _secret_ path. Upon a _login_ path request, user must authenticate themselves to proceed (due to the "WWW Authenticate" header). Once user inputs username and password, client sends request back with an additional header named "Authentication" with the value set as base64 encoding of username and password concatenated seperated by a colon, preceded by unencrypted authentication-type (in this case "Basic"). If user exists in server "database" (which is a simple keyfile in our server's case with usernames and associated encoded passwords) and has provided matching passwords associated with that username, user is authenticated. If not, server responds with a 401 UNAUTHORIZED response offering user to attempt to log in again.

* #### Passwords Encoding Method
To decrease our server's vulnerability, passwords associated with users in keyfile are encrypted with a method that make potential attackers less likely to be able to obtain passwords from keyfile. This method is appending a so-called _salt_ to the password, namely a string which is a randomly generated string of some length (we chose length of each salt to be 64 as we considered that length to be sufficient and secure). After appending the salt string to password, this concatenated string is hashed 10.000 times to achieve multiple hashing. The iterations slow down potential attackers, making our server slightly less vulnerable and passwords from keyfile essensially harder to decode. <br/>

**PLEASE NOTE** that this encoding method is responsible for our server taking relatively long to initiate and authenticate users. When server is initiated a keyfile is generated in the file from where the server is run with authorized users and encoded passwords. Due to passwords for each user being encoded by 10.000 iterations of hashing, the server takes a while to start. Authentication also requires 10.000 iterations of hashing of user provided login information in order match user inputted password with user password in keyfile. 

* ### Minimal Information Flow
**Communication over HTTPS is private** as a certificate is provided for the SSL port to encrypt connections. Only those with the certificate can properly decode any communication over the SSL port (of course, attackers could potentially decrypt communications but attacks are harder over HTTPS connections, thus HTTPS communications as present in our server is still considered private). Another important feature in our implementation that enhances HTTPS privacy is minimal information flow. The only paths that could possibly result in unexpected information flow are _login_ and _secret_ because that's where authentication is required. However, our server doesn't send any information back to client that they do not need. For example, when the client attempts to authenticate themselves and is not successful, the server doesn't specify why it the authentication was unsuccessful. This functionality is pruposely not enhanced as it means that we do not give the client any information that it does not absoluetly require. For example, client only needs to know that authentication was unsuccessful when requesting the _login_ path and client is aware of this when server responds with 401 UNAUTHORIZED. Why authentication is unsuccessful is therefore potentially redundant for a server on such minimal scale. Same goes for _secret_ path requests; the only information sent back to client if they try to access a page where authentication is required is a http response with status code 401: UNAUTHORIZED if authentication failed, otherwise 200 OK. Hence, no unexpected information flow is present in communications between our server and a client.

* ### HTTP Basic Authentication Vulnerabilities
We use HTTP basic authentication to authenticate user. However, **HTTP basic authentication is not secure**. This is because basic authentication is extremely vulnerable to packet sniffing, i.e. when network is monitored and information such as passwords can be decoded from it easily. This is due to the passwords being sent in base64 encoding which is easily converted to plaintext. Another issue with basic authentication is that passwords are repeatedly sent, f.x. when user is authenticated already he sends the authorization header along with their request each time he tries to accesses some URL that requires authentication. This implies that client caches the authentication, increasing the HTTP basic authentication's vulnerability. <br/>
Authentication over SSL is however much more secure. This is because when a connection is secured by SSL the communicaion becomes encrypted, making packet sniffing harder as not only the passwords need to be decrypted but the entire SSL traffic as well. Therefore it's necessary to allow secure authentication over SSL only. (However, basic authentication over SSL still has it's vulnerabilities such as passwords still being repeatedly sent between client and server meaning passwords potentially could eventually be decrypted, but is more secure than basic authentication over HTTP).
