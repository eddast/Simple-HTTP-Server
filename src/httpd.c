

/*  =================================================================
 *
 *		T-409-TSAM Computer Networks
 *		Reykjavik University
 *		Programming Assignment 3: HTTP part 2
 *		Assignment Due: 6.11.2017
 *		Authors: Arnar Freyr and Edda Steinunn
 *
 *  ================================================================= */


#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <time.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>


/**************************************************
 *      FUNCTION DECLARATIONS AND CONSTANTS
 ***************************************************/


enum methods	{ GET = 1, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH };
enum status	{ OK = 200, CREATED = 201, BADREQUEST = 400, UNAUTHORIZED = 401, NOTFOUND = 404, INTERNALSERVERERROR = 500, NOTIMPLEMENTED = 501 };


typedef struct gchar_pair { gchar* key; gchar* value; } gchar_pair;
typedef struct dictionary { int length; gchar_pair contents[1024]; } dictionary;


const int MAX_CONNS = 20;

void	to_log_file			( GString* single_log );	// Appends a single log to log file

void	parse_request 			( GString message[],		// Parses request recieved from client
					  GString* response[],
					  int* connection,
					  struct sockaddr_in client,
					  GString* single_log[] );

int	parse_method 			( GString* method );		// Returns enum equivalent integer from a method string description

int	parse_request_line 		( GString* request_line,
					  int* method_,
					  gchar* http_version[],
					  gchar* URI[],
					  dictionary* QURIs);

int	parse_request_headers		( gchar* message );		// Individually examines request headers

void	construct_error_message		( gchar* URI,
					  int method,
					  gchar* http_version,		// Constructs an error message if status code is not 200 or 201
					  int status_code,
					  GString* response[] );

GString* split_gstring_in_two 		( GString* old_gstr,		// Splits GString on delimeter, returns part before delimeter
					  char delimeter[] );		// Alters parameter GString to match string after delimeter

void	generate_get_response		( int* connection,		// Generates response to a valid GET request from client
					  gchar* http_version,		// Bases response on values parsed from client request
					  gchar* URI,
					  dictionary QURIs,
					  dictionary cookies,
					  gchar* host,
					  int status_code,
					  GString* response[],
					  struct sockaddr_in client );

void	generate_head_response		( int* connection,		// Generates response to a valid HEAD request from client
					  gchar* http_version,		// Bases response on values parsed from client request
					  gchar* URI,
					  dictionary QURIs,
					  dictionary cookies,
					  gchar* host,
					  int status_code,
					  GString* response[],
					  struct sockaddr_in client);

void	generate_post_response		( int* connection,		// Generates response to a valid POST request from client
					  gchar* http_version,		// Bases response on values parsed from client request
					  GString* message,
					  gchar* URI,
					  dictionary QURIs,
					  dictionary cookies,
					  gchar* host,
					  int status_code,
					  GString* response[],
					  struct sockaddr_in client );

void	generate_status_line		( gchar* http_version,		// Appends a status line to parameter message
					  int status_code,		// Sends in client specified HTTP version
					  GString* message[] );		// Along with status code and constructs a reason phrase to match it

GString* generate_post_body		( gchar* URI,			// Generates content for a POST response
					  dictionary QURIs,
					  dictionary cookies,
					  gchar* host,
					  struct sockaddr_in client );

GString*  list_QURIs 			( dictionary QURIs );		// Generates HTML unordered list of query URI parameters
GString*  generate_body			( gchar* URI,			// Generates content for a GET response
					  dictionary QURIs,
					  dictionary cookies,
					  gchar* host,
					  struct sockaddr_in client );

int 	parse_header_fields		( GString message[],		// Parses header fields into dictionary
					  dictionary* dict,
					  dictionary* cookies );

GString* parse_header_field		( GString header_field[],	// Parses a single header field, extracting it's name and value
					  GString* field_name[]);

GString* generate_error_content		( int status_code );		// Generates error content given a status code, explaining what went wrong

void 	update_log			( GString* single_log[],	// Generates a single log upon a request (valid or invalid)
					  struct sockaddr_in client,
					  int method_,
					  gchar* host,
					  gchar* URI,
					  int status_code );

gchar*	get_method			( int method_ );		// Returns gchar equivalent of enum int value method

int	terminate_prog			( struct pollfd poll_[],
					  int poll_size,		// Terminate program on error, closing each connections active in poll structure
					  SSL* ssl[] );			// ensuring client feedback on error

void    QURIs_to_dict                   ( GString* QURI,                // Parses each component name and value of query part of URI and adds to dicitonary
                                          dictionary* dict );

int	print_certificates		( SSL *ssl );			// Prints loaded certificates from SSL structure

SSL_CTX* init_SSL_structure		( );				// Initiates OpenSSL structure

void	shutdown_connection		( int* pollfd,			// Shuts down connection appropriately
					  SSL* ssl );

void	initiate_authorization		( );				// writes authorized user key file if none exists

gchar*	decode_keyfile_value		( gchar* gk_filename,		// Returns decoded value associated with key from key file
					  gchar* group,
					  gchar* key ); 

int	check_authorization		( dictionary header_fields,
					  struct sockaddr_in client );	// Checks whether authorization is valid

int	check_validity			( GString* encryption,		// Checks validity given user/password encryption in keyfile
					  gchar* user[] );

void	log_authentication		( int validity,
					  struct sockaddr_in client,
					  gchar* user );		// Appends authentication log to logfile

void	keyfile_add_entry		( GKeyFile *keyfile,		// Adds authenticated user to keyfile
					  gchar* group,
					  gchar* key,
					  guchar* value );

gchar*	generate_random_string		( int str_len );		// Generates random string of length str_len

void	add_user			( GKeyFile *gk_file,		// Encrypts password appropriately and adds user to keyfile
					  gchar* username,
					  gchar* password,
					  gchar* salt );

unsigned char*	hash_pass		( gchar* password, 
					  gchar* salt);

// Dicitonary structure based functions

void	dictionary_insert		( dictionary* dict,		// Adds key-value gchar pair to dictionary sent in
					  gchar* key,
					  gchar* value );

gchar*	dictionary_search		( dictionary dict,		// Searches parameter dictionary for key and returns it's value (NULL if not found)
					  gchar* key );

void	dictionary_deallocate		( dictionary* dict);		// Deallocates each key-value pairs in dictitonary






/***********************************
 *	    MAIN FUNCTION
 ************************************/


int main ( int argc, char *argv[] ) {

	if ( argc == 3 ) {

		printf ( "Initializing authorization file, please wait...\n" );
		// Initialize authorized users file (users + passwords encoded)
		initiate_authorization ( );
		printf ( "Authorization file initialization complete\n");

		// Initialize SSL structure and certificates
		SSL_CTX *ctx = init_SSL_structure ( );
		SSL* ssl[150] = { NULL };
		
		// Keeps elapsed time of inactivity for each active connection
		// Used to initiate timeout for a specified connection
		time_t connections_start[150] = { 0.0 };
		int is_persistent[150] = { 0 };

		// Creating a socket using default protocol
		// Server initialized/null reseted
		int sockfd; struct sockaddr_in server;
		int SSL_sockfd; struct sockaddr_in SSL_server;
		struct sockaddr_in client[150] = { {0} };
		sockfd = socket ( AF_INET, SOCK_STREAM, 0 );
		SSL_sockfd = socket ( AF_INET, SOCK_STREAM, 0 );

		// Set sockets to be non blocking
		fcntl ( sockfd, F_SETFL, O_NONBLOCK );
		fcntl ( SSL_sockfd, F_SETFL, O_NONBLOCK );
	
		// Initiating servers and specifying their communiation domain
		memset ( &server, 0, sizeof( server ) );
		memset ( &SSL_server, 0, sizeof( server ) );
		server.sin_family = AF_INET; SSL_server.sin_family = AF_INET;

		// Converting arguments from host byte order to network byte order
		// Then binding addresses to sockets using arguments
		server.sin_addr.s_addr = htonl( INADDR_ANY ); server.sin_port = htons( atoi( argv[1] ) );
		SSL_server.sin_addr.s_addr = htonl ( INADDR_ANY ); SSL_server.sin_port = htons ( atoi( argv[2] ) );
		bind ( sockfd, ( struct sockaddr * ) &server, ( socklen_t ) sizeof( server ) );
		bind ( SSL_sockfd, ( struct sockaddr * ) &SSL_server, ( socklen_t ) sizeof( SSL_server ) );

		// The port needs to be listened to before recieving messages
		// Terminates on listening error
		// Backlog of 20 (MAX_CONNS) connection is allowed
		if ( listen( sockfd, MAX_CONNS ) < 0 ) {
			printf ( "Error listening to port: %s\nServer shutting down\n", argv[1] ); return -1;
		} printf( "Server listening on port: %s\n", argv[1] );
		if ( listen( SSL_sockfd, MAX_CONNS ) < 0 ) {
                        printf ( "Error listening to port: %s\nServer shutting down\n", argv[2] ); return -1;
                } printf( "Server listening on port: %s\n\n", argv[2] );


		printf ( "====================\n\n" );


		// Variables needed for enabling parallel connections
		int time_out; struct pollfd poll_[150]; int poll_size = 2;

		// Initiating poll structure before starting server's function
		// poll[0] set to the listening socket in order to accept new connections
		// when appropriate in each iteration
		memset( poll_, 0 , sizeof( poll_ ) );
		poll_[0].fd = sockfd; poll_[1].fd = SSL_sockfd;
		poll_[0].events = POLLIN; poll_[1].events = POLLIN;
		time( &connections_start[0] ); time ( &connections_start[1] );
		time_out = 1000; // checks for timeout every 1s


		while ( 1 ) {

			int connection = 0;
			
			// Poll ( ) initiated for parallel connection			
			if ( poll ( poll_, poll_size, time_out ) < 0 ) {
				printf ( "An error encountered establishing parallel connections\n");
				return terminate_prog( poll_, poll_size, ssl );
			}
			
			// Iterate through each active connection
			int p_size = poll_size;
			for ( int i = 0; i < p_size; i++ ) {

				// Set timeout for active connection:
				// Sets current time and checks how much time has passed
				// since last request on connection
				time_t curr = 0.0; time(&curr);
				double elapsed = difftime( curr, connections_start[i] );
				 				
				// If 30 seconds have not passed since this connection 
				// and no new events are occurring on it move on
				if (i != 0 && i != 1&& elapsed >= 30) { } 
				else if( poll_[i].revents == 0 ) { continue; }

				// If we are currently exploring the unencrypted listening socket
				// in poll structure we need to accept the connection
				if ( poll_[i].fd == sockfd ) {

					int new_sock = 0;

					while ( new_sock != -1) {
						
						// Handshake to client
						// TCP connection is accepted by client
						// connfd variable manages connection
						socklen_t len = ( socklen_t ) sizeof( client[poll_size] );
						new_sock = accept ( sockfd, (struct sockaddr *) &client[poll_size], &len );
						
						// If accept function does not yield an error
						// we add connection to active connection (poll) struct
						// Otherwise we move on to the next active connection
						// without initiating a new one
						if ( new_sock != -1 ) {
								
							poll_[poll_size].fd = new_sock; poll_[poll_size].events = POLLIN; poll_size++;
							printf( "Establishing HTTP connection\n" );
							printf ( "Connection accepted from client\n%d connections currently open\n\n", poll_size-2 );
							printf ( "--------------------\n\n" );
						}
					}
				// If we are currently exploring the encrypted listening socket
				// in poll structure connection must be accepted and SSL added to it for encryption
				} else if ( poll_[i].fd == SSL_sockfd ) {

					int new_SSL_sock = 0;
			
					while ( new_SSL_sock != -1 ) {
						
						// Handshake to client
						// TCP connection is accepted by client
						// connfd variable manages connection
						socklen_t len = ( socklen_t ) sizeof( client[poll_size] );
						new_SSL_sock = accept ( SSL_sockfd, (struct sockaddr *) &client[poll_size], &len );
						
						// If accept function does not yield an error
						// we add connection to active connection (poll) struct
						// Otherwise we move on to the next active connection
						// without initiating a new one
						if ( new_SSL_sock != -1 ) {

							ssl[poll_size] = SSL_new ( ctx );
							SSL_set_fd ( ssl[poll_size], new_SSL_sock );
                                                        printf( "Establishing HTTPS connection\n" );
							poll_[poll_size].fd = new_SSL_sock; poll_[poll_size].events = POLLIN; poll_size++;
							printf ( "Connection accepted from client\n%d connections currently open\n\n", poll_size-2 );
							printf ( "--------------------\n\n" );
						}
					}

				} else {

					while ( 1 ) {
						
						// Checks if this connection has been inactive for 30s or more
						// If so connection is closed and notifies client
						time(&curr); elapsed = difftime(curr, connections_start[i]);	
						if ( elapsed >= 30 && (double)connections_start[i] != 0.0 ) {
							
							printf( "Connection no %d timed out\nClosing connection\n\n", i-1 );
							printf ( "--------------------\n\n" );
							shutdown_connection ( &poll_[i].fd, ssl[i] ); break;
						}

						// SSL handshake if appropriate
						// Terminates connection if accept fails
						if ( is_persistent[i] == 0 && ssl[i] != NULL ){
							
							if ( SSL_accept ( ssl[i] ) <= 0 ) {

								printf ( "SSL handshake failed\nClosing connection\n\n" );
								printf ( "--------------------\n\n" );	
								shutdown_connection ( &poll_[i].fd, ssl[i] ); break;
							} else { printf ( "SSL handshake completed - connection secure\n" ); }
						}

						// Recieve via SSL if on buffer appropriate, otherwise receive normally
						gchar messg[1024] = "\0"; int n = 0;
						if ( ssl[i] == NULL )	{ n = recv( poll_[i].fd, messg, sizeof( messg ), 0 );	}
						else			{ n = SSL_read ( ssl[i], messg, sizeof ( messg ) );	}

						if( n == 0 ) {
							
							// If client closes connection we close connection
							printf ( "Client closed connection no %d\nClosing connection\n\n", i-1 );
							printf ( "--------------------\n\n" );
							shutdown_connection ( &poll_[i].fd, ssl[i] ); break;
							
						} else if (n != -1) { // no error from recieving message

							// Parse recieved request
							// Takes appropriate actions with it
							// Determines response to client
							// Alters log string
							printf ( "Request recieved from client\n" );
							GString* message = g_string_new ( messg );
							GString* response = g_string_new ( "" ); GString* single_log = g_string_new ( "" );
							parse_request ( message, &response, &connection, client[i], &single_log );
							g_string_free ( message, 1 );
							is_persistent[i] = connection;

							// Setting timeout value for connection if it's a keep-alive connection
							// Re-establishes connection after 30s of inactivity on a keep-alive connection
							// ( Code adapted from teacher's TCP server lecture code )
							if( connection == 1 ) { time(&connections_start[i]); }

							// Printing request info into log file before responding
							to_log_file ( single_log ); g_string_free ( single_log, 1);

							// Send response message back to client
							if ( ssl[i] == NULL )	{ send( poll_[i].fd, response->str, (size_t) response->len, 0 ); }
							else			{ SSL_write ( ssl[i], response->str, (size_t) response->len ); }
							printf ( "Response successfully sent to client\n" );	
							g_string_free ( response, 1 );
							
							// On a closed connection we always close connection
							if (connection == 0) {
							
								// Close the connection after serving message fragment
								printf ( "Closing current connection\n\n" );
								printf ( "--------------------\n\n" );
								shutdown_connection ( &poll_[i].fd, ssl[i] ); break;

							} else { 
								printf ( "Connection no %d kept open\n\n", i-1 ); 
								printf ( "--------------------\n\n" ); break; 
							}

						} else {
						
							// If errno from recieve is EAGAIN we want to revisit connection, not terminate it
							// Otherwise we have an error and want to close the connection
							if ( errno != EAGAIN ) {

								printf ( "Closing current connection\n\n" ); connection = 0;
								printf ( "--------------------\n\n" );
								shutdown_connection ( &poll_[i].fd, ssl[i] ); break;
							}
						}
					}
				}
			}
			
			// If fd of a connection has the value -1 after previous iteration, meaning it is closed
			// We wish to remove it from active connection (poll) structure
			for (int i = 0; i < poll_size; i++ ) {

				if (poll_[i].fd == -1) {

					connections_start[i] = 0.0;
					for ( int j = i; j < poll_size; j++) {
						poll_[j].fd = poll_[j+1].fd;
						is_persistent[j] = is_persistent[j+1];
						ssl[j] = ssl[j+1];
						connections_start[j] = connections_start[j+1];
						client[j] = client[j+1];
						
					} poll_size--; p_size--; i--;
				}
			}			
		}

	} else { printf( "ERROR: Incorrect number of parameters\nServer shutting down\n" ); }
}





/******************************************
 *	IMPLEMENTATION OF FUNCTIONS
 ******************************************/


// Shuts down connection
void shutdown_connection ( int* pollfd, SSL* ssl ) {

	if ( *pollfd != -1 ) { 	

		if ( ssl != NULL) { 
			SSL_shutdown ( ssl ); 
			SSL_free ( ssl ); 
		}
		shutdown( *pollfd, SHUT_RDWR ); close( *pollfd );
	} *pollfd = -1;
}

// Prints certificates of SSL structure
int print_certificates ( SSL *ssl ) {

	X509 *certificate; char *line;	
	certificate = SSL_get_certificate ( ssl );
	if ( certificate != NULL ) {
		line = X509_NAME_oneline ( X509_get_subject_name ( certificate ), 0, 0);
		printf ( "Certificate: %s\n", line );
		free ( line ); free ( certificate ); return 1;
	} else { return -1; }
}

// Decode encoded value associated with parameter key and group
// Returns NULL if no value associated with parameter key is found
gchar* decode_keyfile_value ( gchar* gk_filename, gchar* group, gchar* key ) {

	GKeyFile* keyfile = g_key_file_new( );
	g_key_file_load_from_file ( keyfile, gk_filename, G_KEY_FILE_NONE, NULL);

	gchar *passw64 = g_key_file_get_string ( keyfile , group, key, NULL );

	// If user is found in database it is decoded from base64
	if ( passw64 != NULL ) {
		gsize dcode_len; gchar *passwd = (gchar*) g_base64_decode ( passw64, &dcode_len );
		g_free ( passw64 ); g_key_file_free ( keyfile );
		return passwd;
	} else {
		g_free ( passw64 ); g_key_file_free ( keyfile );
		return NULL;
	}
}

// Initiate authorization for one user (admin/password)
void initiate_authorization  ( ) {

	GKeyFile *gk_file = g_key_file_new ( );

	// a random seed for random strings
	srand ( time ( NULL ) );
	
	gchar* admin_salt = generate_random_string ( 64 );

	// Add salt associated with users
	keyfile_add_entry ( gk_file, "Salt", "admin", (guchar*) admin_salt );

	// Add salt to user passwords, then inserting into keyfile
	add_user ( gk_file, "admin", "password", admin_salt );
	g_free ( admin_salt );

	// Save file in directory or overwrite existing file
	g_key_file_save_to_file ( gk_file, "users.ini", NULL );
	g_key_file_free ( gk_file );
}

// Adds user to database with relevant salting and hasing
void add_user ( GKeyFile *gk_file, gchar* username, gchar* password, gchar* salt ) {

	// Hashes password with the salt string appended to it
	// Then adds entry to database, encoding it in base64 along the way
	unsigned char* password_encrypted = hash_pass ( password, salt );
	keyfile_add_entry ( gk_file, "Users", username, password_encrypted );	
	free ( password_encrypted );

}

// Hashes password with salt appended to password
// Uses 10.000 iterations of hashing
// Then returns the encrypted password
unsigned char* hash_pass ( gchar* password, gchar* salt ) {
	
	int keylen = 64; const EVP_MD *digest = EVP_sha256( );
	unsigned char* password_encrypted = (unsigned char *) malloc( sizeof ( unsigned char ) * keylen + 1 );
	PKCS5_PBKDF2_HMAC(	password, strlen ( password ),
				(guchar*) salt, sizeof ( salt ), 10000,
				digest, keylen, password_encrypted);
	password_encrypted[64] = '\0';

	return password_encrypted;
}

// Adds entry to keyfile specified with it's value encoded
void keyfile_add_entry ( GKeyFile *keyfile, gchar* group, gchar* key, guchar* value ) {

	gchar* value64 = g_base64_encode ( value, strlen ( (gchar*) value ) );	
	g_key_file_set_string ( keyfile, group, key, value64 );
	g_free ( value64 );
}

// Generates random string with digits and characters of length str_len
gchar* generate_random_string ( int str_len ) {
	
	GString* random_gstring = g_string_new ( "" );

	// Let our character set consist of 0-9 in numbers
	// And of a-z in the English alphabet, both lowercase and upper case
	// For a well randomized string
	GString* character_set = g_string_new ( "0123456789" );
	g_string_append ( character_set, "9abcdefghijklmnopqrstuvwxyz" );
	g_string_append ( character_set, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" );

	while ( str_len > 0) {
		
		// Select random index as next index for new string
		int random_idx = ( double ) rand ( ) / RAND_MAX * (character_set->len - 1);
		gchar* fragment = g_strdup_printf ( "%c", character_set->str[random_idx] );
		g_string_append ( random_gstring, fragment );
		g_free ( fragment ); str_len--;
	}
	
	gchar* random_string = g_strdup ( random_gstring->str );
	g_string_free ( character_set, 1 ); g_string_free ( random_gstring, 1 );
	
	return random_string;

}

// Initiates CTX structure and it's certificates
SSL_CTX* init_SSL_structure ( ) {

	// Initiates library and it's error strings
	// Initiates ctx from server method
	SSL_library_init ( ); SSL_load_error_strings ( );
	const SSL_METHOD *mth = SSLv23_server_method( );
	SSL_CTX *ctx = SSL_CTX_new ( mth );

	// File locations for key and certificates both in root and parent directory
	const char* crt_file = "../fd.crt"; const char* crt_name = "fd.crt";
	const char* key_file = "../fd.key"; const char* key_name = "fd.key";
	
	// Set CTX session ID for client because we use client sertificate
	static int SSL_session_ID = 1;
	SSL_CTX_set_session_id_context 	( ctx, (void*) &SSL_session_ID,
					  sizeof ( SSL_session_ID ));

	// Load certificates
	if ( SSL_CTX_use_certificate_file ( ctx, crt_file, SSL_FILETYPE_PEM ) <= 0 ) {
		if ( SSL_CTX_use_certificate_file ( ctx, crt_name, SSL_FILETYPE_PEM ) <= 0 ) {	return NULL; }
	  // Load private key
	} if ( SSL_CTX_use_PrivateKey_file ( ctx, key_file, SSL_FILETYPE_PEM ) <= 0 ) {
		if ( SSL_CTX_use_PrivateKey_file ( ctx, key_name, SSL_FILETYPE_PEM ) <= 0 ) { return NULL; }
	  // Loads verify locations
	} if ( SSL_CTX_load_verify_locations ( ctx, crt_file, NULL ) <= 0 ) {
		if ( SSL_CTX_load_verify_locations ( ctx, crt_name, NULL ) <= 0 ) { return NULL; }
	} SSL_CTX_set_verify ( ctx, SSL_VERIFY_PEER, NULL ); SSL_CTX_set_verify_depth ( ctx, 1 );

	// Return CTX structure
	return ctx;
}


// Terminates on error, shutting down every active connection appropriately
int terminate_prog ( struct pollfd poll_[], int poll_size, SSL* ssl[] ) 
{	 
	printf( "Server shutting down\n" );

	for( int i = 0; i < poll_size; i++ ) {

		shutdown( poll_[i].fd, SHUT_RDWR ); close( poll_[i].fd );
		if (ssl[i] != NULL) { SSL_free ( ssl[i] ); }
	}

	return -1;
}

// Prints request to log file
// Either creates file HTTPlog.log or appends to it
void to_log_file ( GString* single_log ) {

        FILE* file = fopen ( "HTTPlog.log", "a+" );
	if ( !file ) { printf ( "Unable to log request\n" ); return; }
	else {
		fprintf ( file, "%s",  single_log->str );
		fclose(file);
	}
}

// Parses request sent from client, splitting into request line, headers and message body
// Then uses parsed information to construct a response message back to client
void parse_request ( GString message[], GString* response[], int* connection, struct sockaddr_in client, GString* single_log[] ) {
	
	// Initializing dictionaries for headers, cookies and URI query components
	dictionary header_fields 	=	{ 0, {{NULL}} };
	dictionary cookies 		= 	{ 0, {{NULL}} };
	dictionary QURI_components	= 	{ 0, {{NULL}} };
	
	// Preserves status code throughout parsing
	int status_code = OK;

	// Values initialized; achieved by parsing
	// FROM REQ LINE:
	int method_; gchar* http_version; gchar* URI;

	// PARSING REQUEST LINE
	// Send in first line to parse request line
	// Goal: find method and http version
	// If request line is fine, status code remains 200
	GString* request_line = split_gstring_in_two ( message, "\n" );
	status_code = parse_request_line ( request_line, &method_, &http_version, &URI, &QURI_components );

	// A favicon.ico URI returns a 404 error back to client
	// (A feature suggested by teacher)
	if ( strcmp ( URI, "/favicon.ico" ) == 0 ) { status_code = NOTFOUND; }

	// If no error yet, we parse header fields
	*connection = -1;
	if ( status_code == OK || status_code == CREATED ) { status_code = parse_header_fields( message, &header_fields, &cookies ); }
	else if ( status_code == BADREQUEST ) { construct_error_message ( URI, method_, "HTTP/1.1", status_code, response ); }
	else { parse_header_fields (message, &header_fields, &cookies ); }
	
	// Status code determinated by authorization validty if client
	// requests /login or /secret as URI as those paths require authentication
	if ( status_code == OK && ( g_str_has_prefix ( URI, "/login" ) || g_str_has_prefix ( URI, "/secret" ) ) ) {
		status_code = check_authorization ( header_fields, client );
	}

	// Parse connection type and host name from header fields dictionary 
	gchar* connection_type = dictionary_search ( header_fields, "Connection" );
	if( connection_type != NULL ) {
		if	( strcmp ( connection_type, "keep-alive" ) == 0 )	{ *connection = 1; }
		else if ( strcmp ( connection_type, "closed" ) == 0 )		{ *connection = 0; }
		g_free ( connection_type );
	}
	gchar* host = dictionary_search ( header_fields, "Host" );

	// If no connection header field was specified by client
	// We use the default connection type for client specified HTTP version
	if( *connection == -1 ) {
		if ( strcmp ( http_version, "HTTP/1.0") == 0 ) { *connection = 0; }
		else { *connection = 1; }
	}

	// Changes in status code mean error
	// Must return to main with an error message
	if( status_code != OK && status_code != CREATED)	{ construct_error_message ( URI, method_, http_version, status_code, response ); }
	else {

		// Construct message however specified by request method
		if 	( method_ == GET  )	{ generate_get_response  ( connection, http_version, URI, QURI_components, cookies, host, status_code, response, client ); }
		else if	( method_ == HEAD )	{ generate_head_response ( connection, http_version, URI, QURI_components, cookies, host, status_code, response, client ); }
		else if ( method_ == POST )	{ generate_post_response ( connection, http_version, message, URI, QURI_components, cookies, host, status_code, response, client ); }
	}

	// Update request log (already has a time stamp)
	update_log ( single_log, client, method_, host, URI, status_code );
	
	// MEMORY CLEANUP: Free gchars and gstring variables if neccesary
	// Deallocate dictionaries' gchar pairs
	if ( http_version != NULL ) { g_free ( http_version ); }
	if ( URI != NULL ) { g_free ( URI ); }
	if ( host != NULL ) { g_free ( host ); }
	if ( request_line != NULL ) { g_string_free ( request_line, 1 ); }
	dictionary_deallocate ( &header_fields );
	dictionary_deallocate ( &cookies );
	dictionary_deallocate ( &QURI_components );
}

// Gets gchar equivalent of an enum integer method
gchar* get_method ( int method_ ) {

	gchar* mtd;

	switch ( method_ ) {
		case 1:		mtd = g_strdup ( "GET" );	break;
		case 2:		mtd = g_strdup ( "HEAD" );	break;
		case 3:		mtd = g_strdup ( "POST" );	break;
		case 4:		mtd = g_strdup ( "PUT" );	break;
		case 5:		mtd = g_strdup ( "DELETE" );	break;
		case 6:		mtd = g_strdup ( "CONNECT" );	break;
		case 7:		mtd = g_strdup ( "OPTIONS" );	break;
		case 8:		mtd = g_strdup ( "TRACE" );	break;
		case 9: 	mtd = g_strdup ( "PATCH" );	break;
		default:	mtd = g_strdup ( "UNDEFINED" ); break;
	}

	return mtd;
}

// Formats log file
void update_log ( GString* single_log[], struct sockaddr_in client, int method_, gchar* host, gchar* URI, int status_code ) {

	time_t now = time( NULL );
	struct tm *now_tm = gmtime ( &now );
	char iso_8601[] = "YYYY-MM-DDTHH::MM:SSZ";
	strftime ( iso_8601, sizeof ( iso_8601 ), "%FT%R:%S" , now_tm );

	g_string_append ( *single_log, iso_8601 );
	g_string_append ( *single_log, " : " );

	gchar* client_ip = g_strdup ( inet_ntoa ( client.sin_addr ) );
	g_string_append ( *single_log,  client_ip);
	g_free ( client_ip );
	g_string_append ( *single_log, ":" );

	gchar* client_port = g_strdup_printf( "%i", client.sin_port );
	g_string_append ( *single_log,  client_port);
	g_free ( client_port );

	g_string_append ( *single_log, " " );

	gchar* mthd = get_method (method_);
	g_string_append ( *single_log, mthd);
	g_free ( mthd );

	g_string_append ( *single_log, " http://" );
	g_string_append ( *single_log, host );
	g_string_append ( *single_log, URI );
	g_string_append ( *single_log, " : " );
	char status_code_str[3] = "\0";
	sprintf( status_code_str, "%d", status_code );
	g_string_append ( *single_log, status_code_str);
	g_string_append ( *single_log, "\n" );
}

// Check whether authorization header field matches user and password in keyfile
int check_authorization ( dictionary header_fields, struct sockaddr_in client ) {
	
	// Default is ofcourse unauthorized
	int ret = UNAUTHORIZED;

	// Search for value for authentication header in header fields dictionary
	gchar* login_info = dictionary_search ( header_fields, "Authorization" );
	gchar* user = NULL;

	// If no authorization header exists in header dictinary, operation is unauthorized
	// Otherwise we decrypt authorization and check if values match authorized users in keyfile
	if ( login_info == NULL ) { g_free ( login_info ); return UNAUTHORIZED; }
	else {
		GString* encryption = g_string_new ( login_info ); 
		GString* authorization_type = split_gstring_in_two ( encryption, " ");

		if ( strcmp ( authorization_type->str, "Basic") != 0 ) { ret = UNAUTHORIZED; }
		else { ret = check_validity ( encryption, &user ); }

		// MEMORY CLEANUP
		g_free ( login_info ); g_string_free ( authorization_type, 1 ); g_string_free ( encryption, 1 );
	}

	// Log authentication attempt to logfile
	log_authentication ( ret, client, user );

	g_free ( user ); // MEMORY CLEANUP

	return ret;
}

// Logs authentication attempt and whether it was successfull
// <timestamp> : <client ip>:<client port> <user> <authenticated/authentication error>
void log_authentication ( int validity, struct sockaddr_in client, gchar* user ) {

	GString* authentication_log = g_string_new ( "" );

	time_t now = time( NULL );
	struct tm *now_tm = gmtime ( &now );
	char iso_8601[] = "YYYY-MM-DDTHH::MM:SSZ";
	strftime ( iso_8601, sizeof ( iso_8601 ), "%FT%R:%S" , now_tm );

	// Timestamp
	g_string_append ( authentication_log, iso_8601 );
	g_string_append ( authentication_log, " : " );

	// client IP
	gchar* client_ip = g_strdup ( inet_ntoa ( client.sin_addr ) );
	g_string_append ( authentication_log,  client_ip);
	g_free ( client_ip );

	g_string_append ( authentication_log, ":" );

	// Client port
	gchar* client_port = g_strdup_printf( "%i", client.sin_port );
	g_string_append ( authentication_log,  client_port);
	g_free ( client_port );

	g_string_append ( authentication_log, " " );

	// User
	g_string_append ( authentication_log, user );

	g_string_append ( authentication_log, " ");

	if ( validity == UNAUTHORIZED )      { g_string_append ( authentication_log, "authentication error\n" ); }
	if ( validity == OK )                { g_string_append ( authentication_log, "authenticated\n" );}

	to_log_file ( authentication_log );

	g_string_free ( authentication_log , 1 );
}

// Checks validity of encrypted value for user/password in keyfile
// Encrypts password after decrypting it from base64 into plaintext
// using same method as passwords are encrypted when entered into database (keyfile)
// Then the two encodings are compared - if they match user is authenticated
int check_validity ( GString* encryption, gchar* user[] ) {

	// User is of course unauthorized by defult
	int ret = UNAUTHORIZED;
	
	// Decrypt username and password from encryption sent in
	// Decryption should yield the format userID:password, so split values on colon
	gsize len; gchar* decryption = ( gchar* ) g_base64_decode ( encryption->str, &len );
	GString* decrypted_password = g_string_new ( decryption );
	GString* decrypted_user = split_gstring_in_two ( decrypted_password, ":" );
	*user = g_strdup ( decrypted_user->str );

	// Locate decrypted password for userID provided by client in keyfile
	// Fetch salt for user, then append that to passwrod and hash it 10.000 times
	// Then match encoded passwords - if they match user is authenticated
	gchar* keyfile_password = decode_keyfile_value ( "users.ini", "Users", decrypted_user->str );
	if ( keyfile_password == NULL) { ret = UNAUTHORIZED; }
	else {
		gchar* keyfile_password_enc = g_base64_encode ( ( guchar* ) keyfile_password, (int) sizeof ( keyfile_password ) );
 
		gchar* keyfile_salt = decode_keyfile_value ( "users.ini", "Salt", decrypted_user->str );
		
		// If no salt exists for user in keyfile user does not exist in keyfile
		// and is therefore not authorized
		if ( keyfile_salt == NULL ) { ret = UNAUTHORIZED; }
		else {
			unsigned char* user_pass = hash_pass( decrypted_password->str, keyfile_salt );
			gchar* hashed_user_pass = g_base64_encode ( user_pass, (int) sizeof ( user_pass ) );


			// If user does not exist in keyfile, operation is unauthorized
			// If user and password match key and value in keyfile, operation is authorized
			// If user exists in keyfile but password do not match, operation is unauthorized
			if      ( keyfile_password == NULL )					{ ret = UNAUTHORIZED; }
 			else if ( strcmp ( keyfile_password_enc, hashed_user_pass ) == 0 )	{ ret = OK; }
			else									{ ret = UNAUTHORIZED; }
		
			g_free ( hashed_user_pass ); free ( user_pass ); // MEMCLEANUP
		}

		g_free ( keyfile_password_enc ); g_free ( keyfile_salt ); // MEMCLEANUP
	}
	g_free ( keyfile_password ); g_free ( decryption );				//MEMCLEANUP
	g_string_free ( decrypted_user, 1 ); g_string_free ( decrypted_password, 1 );	//MEMCLEANUP

	return ret;
}

// Breaks header fields down in their own units
// After execution, if status code is returned as 200 (OK),
// Message variable should contain nothing but the body
int parse_header_fields( GString message[], dictionary* dict, dictionary* cookies ) {

	 if ( strcmp (message->str, "") == 0 ) { return OK; }
	
	// Create header_field placeholder string
	// Will hold each header field with every iteration of loop
	GString* header_field = g_string_new ( " " );

	// Loop stops when header field is empty -- that is double newline encountered
	do {
		g_string_free ( header_field, 1 );
		// Splits message on newline
		// Parsing next header field
		header_field = split_gstring_in_two ( message, "\n");

		// Another edge case check
		if ( header_field->len <= 1 ) { break; }

		// Getting field name by parsing individual header fields
		// Getting their name and value
		GString* field_name;
		GString* field_value = g_string_new ( parse_header_field( header_field, &field_name )->str );
	
		// If parsing of individual header field yields an error,
		// status code becomes 400: bad request
		if ( strcmp (field_value->str, "" ) == 0 ) {

			g_string_free ( header_field, 1 );
			g_string_free ( field_name, 1);
			g_string_free ( field_value, 1);
			return BADREQUEST;
		}
		
		// Cookie header field is also added to the cookie dictionary
		// to facilitate looking for cookies as they can be many in one request
		// (Although our implementation should only receive one cookie,
		// this way our code is more generalized and efficient)
		if ( strcmp ( field_name->str, "Cookie" ) == 0 ) {
			
			while ( strcmp ( field_value->str, "" ) != 0 ) {
				
				// Isolate all names and values for cookies in field
				// Then add to cookies dicitonary
				GString* one_cookie = split_gstring_in_two ( field_value, ";" );
				GString* cookie_name = split_gstring_in_two ( one_cookie, "=" );
				GString* cookie_value = g_string_new ( one_cookie->str );

				dictionary_insert ( cookies, cookie_name->str, cookie_value->str );	

				g_string_free ( one_cookie, 1 );					//MEMCLEANUP
				g_string_free ( cookie_name, 1); g_string_free ( cookie_value, 1);	//MEMCLEANUP
			}
		}
	
		// If no error and not a cookie field, entry added to dictionary for header field
		dictionary_insert ( dict, field_name->str, field_value->str );

		g_string_free ( field_name, 1); g_string_free ( field_value, 1);			//MEMCLEANUP

	}  while ( strcmp ( header_field->str, "" ) != 0 );

	g_string_free ( header_field, 1 );								//MEMCLEANUP

	// If we reach this point without returning bad request status code
	// Parsing of header field was OK - return 200 OK as status code
	return OK;
}

// Parses individual header field
// Stores header field name and value
// Returns NULL if parsing was not OK for parse_header_fields to return an error status code (400)
GString* parse_header_field( GString header_field[], GString* field_name[] ) {

	// Splits on name/value field delimeter
	// Then stores appropriate values
	*field_name = split_gstring_in_two( header_field, ":");
	if ( g_str_has_suffix( (*field_name)->str, " ") ) { return g_string_new( NULL ); }
	if ( g_str_has_prefix( header_field->str, " " )) { g_string_erase( header_field, 0, 1 ); }

	// Returns value of field
	return header_field;
}

// Generates response message for GET requests
// Generates head response as it is, and appends body to it
void generate_get_response ( int* connection, gchar* http_version, gchar* URI, dictionary QURIs, dictionary cookies, gchar* host, int status_code, GString* response[], struct sockaddr_in client ) {

	GString* body = generate_body( URI, QURIs, cookies, host, client );
	generate_head_response ( connection, http_version, URI, QURIs, cookies, host, status_code, response, client );
	g_string_append ( *response, body->str );

	g_string_free ( body, 1 );
}

// Generates body for responses
// Bases on generate_post body (almost the same, but missing final "</body>\n" string)
GString* generate_body ( gchar* URI, dictionary QURIs, dictionary cookies, gchar* host, struct sockaddr_in client ) {

	GString* body = generate_post_body ( URI, QURIs, cookies, host, client );
        g_string_append ( body, "</body>\n" );

	return body;
}

// Generates appropriate body (doesn't close <body> section, done later)
GString* generate_post_body ( gchar* URI, dictionary QURIs, dictionary cookies, gchar* host, struct sockaddr_in client ) {

        GString* body = g_string_new ( "" );

	// Color URL is a special case handled differently:
	// Color returns a HTML page with background color
	// It expects either specification of background color in query part of URI
	// OR a cookie determining last color request from client
	// (If no color is specified and no color cookie exist either, white is the default color)
	if ( g_str_has_prefix ( URI, "/color" ) ) {

		// Check for specified color in query URI components dictionary
		// If no such entry exist check for color cookie in cookie dictitonary
		// If no color cookie exists either for client, white is set
		gchar* bg_color = dictionary_search ( QURIs, "bg" );
		if ( bg_color == NULL ) { 
			
			gchar* cookiecol = dictionary_search ( cookies, "color" );

			if ( cookiecol == NULL) { bg_color = g_strdup ( "white" ); }
			else			{ bg_color = g_strdup ( cookiecol ); g_free ( cookiecol ); }
		}

		g_string_append ( body, "<body style=\"background-color:" );
		g_string_append ( body, bg_color );
		g_string_append ( body, "\">" );
	
		g_free ( bg_color );
	
		return body;
        }

	// Otherwise, carry on as normal, returning appropriate body
	// (host,uri,client address, client port and query parameters)
        g_string_append ( body, "<!DOCTYPE html>\n" );
        g_string_append ( body, "<body>\n" );
        g_string_append ( body, "<p>http://" );
        g_string_append ( body, host );
        g_string_append ( body, URI );
        g_string_append ( body, " " );
	gchar* client_ip = g_strdup ( inet_ntoa ( client.sin_addr ) );
        g_string_append ( body, client_ip );
	g_free ( client_ip );
        g_string_append ( body, ":" );
	gchar* client_port = g_strdup_printf( "%i", client.sin_port );
        g_string_append ( body, client_port );
	g_string_append ( body, "</p>\n" );
	g_free ( client_port );

	// Add query part of URI's parameters if there are any
	// use list_QURIs function to construct an unordered list
	// of query parameters, then append to body
	if ( QURIs.length != 0 ){
		GString* list = list_QURIs ( QURIs );
		g_string_append ( body, list->str );
		g_string_free ( list, 1 );
	}

        return body;
}

// Partitions query part of URI into parameters and creates an unordered list of it
// Returns the HTML list
GString* list_QURIs ( dictionary QURIs ) {

	GString* list = g_string_new ( "Query Parameters:\n" );
	g_string_append ( list, "<ul>\n" );
	
	for ( int i = 0; i < QURIs.length; i++) {	
		g_string_append ( list, "<li>" );
		g_string_append ( list, QURIs.contents[i].key );
		g_string_append ( list, "=" );
		g_string_append ( list, QURIs.contents[i].value );
		g_string_append ( list, "</li>\n" );
	}

	g_string_append ( list, "</ul>\n" );


	return list;
}

// Generates head response with appropriate headers
void generate_head_response ( int* connection, gchar* http_version, gchar* URI, dictionary QURIs, dictionary cookies, gchar* host, int status_code, GString* response[],  struct sockaddr_in client ) {

	GString* body = generate_body( URI, QURIs, cookies, host, client );

	generate_status_line ( http_version, status_code, response );

	if ( *connection == 0 )	{ g_string_append ( *response, "Connection: close\n" ); }
	else			{ g_string_append ( *response, "Connection: keep-alive\n" ); }

	g_string_append ( *response, "Content-Type: text/html; charset=UTF-8\n" );
	g_string_append ( *response, "Content-Length: " );

	gchar* cont_length = g_strdup_printf( "%i", (int) body->len );
	g_string_append ( *response, cont_length );
	g_string_append ( *response, "\n" );
	
	if( g_str_has_prefix ( URI, "/color" ) ) {
		
		gchar* cookie_color = dictionary_search ( QURIs, "bg" );
		if( cookie_color != NULL ) {
		
			g_string_append ( *response, "Set-Cookie:" );
			g_string_append ( *response, " color=" );
			g_string_append ( *response, cookie_color );
			g_string_append ( *response, "\n" );
		}
		g_free ( cookie_color );
	}

	g_string_free ( body, 1 );
	g_free ( cont_length );
	g_string_append ( *response, "\n" );
}

// Generates post response to client
// Sends request line with status code 201 CREATED
// Stores HTML5 body in memory as body concatenated with data sent by client
void generate_post_response ( int* connection, gchar* http_version, GString* message,  gchar* URI, dictionary QURIs, dictionary cookies, gchar* host, int status_code, GString* response[], struct sockaddr_in client ) {

	status_code = CREATED; generate_status_line ( http_version, status_code, response );

	GString* post_content = generate_post_body ( URI, QURIs, cookies, host, client );
	g_string_append ( post_content, message->str );
	g_string_append ( post_content, "</body>\n");
	printf ( "Content: %s\n", post_content->str);

	if ( *connection == 0 ) { g_string_append ( *response, "Connection: close\n" ); }
	else                    { g_string_append ( *response, "Connection: keep-alive\n" ); }
	
	g_string_append ( *response, "Content-Length: " );
	gchar* post_len = g_strdup_printf ( "%i", (int) post_content->len );
	g_string_append ( *response, post_len );
	g_free (post_len);
	g_string_append ( *response, "\n\n" );
	g_string_append ( *response, post_content->str );
	g_string_free ( post_content, 1 );
}

// Generates status line based on status code
void generate_status_line ( gchar* http_version, int status_code, GString* response[] ) {

	// Reason phrase describes status code and is designed to match it
	GString* reason_phrase = g_string_new( "" );
	if ( status_code == OK )			{ g_string_append ( reason_phrase, "OK" ); }
	else if ( status_code == NOTFOUND )		{ g_string_append ( reason_phrase, "NOT FOUND" ); }
	else if ( status_code == BADREQUEST )		{ g_string_append ( reason_phrase, "BAD REQUEST"); }
	else if ( status_code == NOTIMPLEMENTED )	{ g_string_append ( reason_phrase, "NOT IMPLEMENTED"); }
	else if ( status_code == UNAUTHORIZED )		{ g_string_append ( reason_phrase, "UNAUTHORIZED" ); }
	else if ( status_code == INTERNALSERVERERROR)	{ g_string_append ( reason_phrase, "INTERNAL SERVER ERROR" ); }
	else if ( status_code == CREATED )		{ g_string_append ( reason_phrase, "CREATED" ); }

	// Status code set to string
	// In order to add it to GString variable
	char status_code_str[3] = "\0";
	sprintf( status_code_str, "%d", status_code );

	// Appending to empty response message
	// Should take the following form:
	// "http_version SP status_code SP reason_phrase CRLF"
	// HTTP version default: 1.1 since our server does not support future versions
	if 	( !strcmp (http_version, "HTTP/1.0") )	{ g_string_append ( *response, "HTTP/1.0" ); }
	else					 	{ g_string_append ( *response, "HTTP/1.1" ); }
	g_string_append ( *response, " ");
	g_string_append ( *response, status_code_str );
	g_string_append ( *response, " ");
	g_string_append ( *response, reason_phrase->str );
	g_string_append ( *response, "\n" );

	g_string_free ( reason_phrase, 1 );

}


// Split string in two on delimeter
// Alters GString parameter to match GString at and after delimeter
// Returns GString before delimeter
GString* split_gstring_in_two ( GString* old_gstr, char delimeter[] ) {

	// Error checks: Can't split an empty string or one not containing delimeter
	GString* delim_pointer = g_string_new ( g_strstr_len ( old_gstr->str, old_gstr->len, delimeter ) );
	if ( old_gstr->len == 0 ) { return old_gstr; }
	if ( delim_pointer == NULL ) { return old_gstr; }


	// New GString old GString
	// Old string is then split at delimeter
	// New string is truncated at beginning of newly altered old string
	GString* new_gstr = g_string_new ( old_gstr->str );
	g_string_overwrite ( old_gstr, 0, delim_pointer->str );
	g_string_truncate  ( old_gstr, delim_pointer->len );
	g_string_truncate ( new_gstr, ( new_gstr->len - old_gstr->len ) );
	if ( old_gstr->len != 0 ) { g_string_erase ( old_gstr, 0, 1 ); }

	g_string_free ( delim_pointer , 1 );

	// Returns GString containing characters before delimeter
	return new_gstr;
}

// Parses request line sent from client
int parse_request_line ( GString* request_line, int* method_, gchar* http_version[], gchar* URI[], dictionary* QURIs ) {

	if ( strcmp ( request_line->str, "" ) == 0 ) { return BADREQUEST; }

	// Parse method from request line
	// (always first in a request line)
	GString* method = split_gstring_in_two ( request_line, " ");

	if ( strcmp ( request_line->str, "" ) == 0 ) { g_string_free ( method, 1 ); return BADREQUEST; }

	// Method variable corresponds to method ENUM
	// ( Currently supported methods 1-3 )
	( *method_ ) = parse_method ( method );

	g_string_free ( method, 1 );

	// Split URI to isolate the query part of URI in a GString
	// Then write query URI components to the QURIs dictionary
	GString* tmp_QURI = split_gstring_in_two ( request_line, " " );
	GString* tmp_URI = split_gstring_in_two ( tmp_QURI, "?" );
	GString* all_QURIs = g_string_new ( tmp_QURI->str );	
	QURIs_to_dict ( all_QURIs, QURIs );
	g_string_free ( all_QURIs, 1 );

	// FIX URI: Appends query URI components back onto URI to re-complete it
	// if appropriate after seperating the two parts
	// Then placing it in char variable passed back to main parser
	if( (*QURIs).length != 0 ) {
		g_string_append ( tmp_URI, "?" );
		g_string_append ( tmp_URI, tmp_QURI->str );
	} *URI = g_strdup ( tmp_URI->str );

	g_string_free ( tmp_URI, 1 );
	g_string_free ( tmp_QURI, 1 );

	if ( strcmp (request_line->str, "" ) == 0 ) { return BADREQUEST; } 

	// Parses HTTP version specified from request line
	// Should be rest of request line
	GString* tmp_httpvers = split_gstring_in_two ( request_line, "\n");
	*http_version = g_strdup( tmp_httpvers->str );
	g_string_free ( tmp_httpvers , 1);

	// Return status code after reading in request line
        // Depends on method specified
	if	( ( *method_ ) == NOTIMPLEMENTED )	{ return NOTIMPLEMENTED; }
	else if	( ( *method_ ) > 3 )			{ return NOTIMPLEMENTED; }
	else						{ return OK; }
}

// Isolates query part of URI's components
// Insertes component name (key) and it's value to a dictionary
void QURIs_to_dict ( GString* QURI, dictionary* dict ) {

	while ( strcmp ( QURI->str, "" ) != 0 ) {

		GString* QURI_component = split_gstring_in_two ( QURI, "&" );
 		GString* QURI_key = split_gstring_in_two ( QURI_component, "=" );
		GString* QURI_value = g_string_new ( QURI_component->str );

		dictionary_insert ( dict, QURI_key->str, QURI_value->str );

		g_string_free ( QURI_component, 1 );
 		g_string_free ( QURI_key, 1 );
		g_string_free ( QURI_value, 1 );

	}
}


// Parses method - also parses methods not implemented by server, making future expansion possible
int parse_method ( GString* method ) {

	gchar* mthd = g_strdup ( method->str );
	int method_code = NOTIMPLEMENTED;

	// Valid HTTP methods
	if ( !strcmp ( mthd, "GET" ) )		{	method_code = GET;		}
	else if ( !strcmp ( mthd, "HEAD" ) )	{	method_code = HEAD;		}
	else if ( !strcmp ( mthd, "POST" ) )	{	method_code = POST;		}
	else if ( !strcmp ( mthd, "PUT") )	{	method_code = PUT;		}
	else if ( !strcmp ( mthd, "DELETE" ) )	{	method_code = DELETE;		}
	else if ( !strcmp ( mthd, "CONNECT" ) )	{	method_code = CONNECT;		}
	else if ( !strcmp ( mthd, "OPTIONS" ) )	{	method_code = OPTIONS;		}
	else if ( !strcmp ( mthd, "TRACE" ) )	{	method_code = TRACE;		}
	else if ( !strcmp ( mthd, "PATCH" ) )	{	method_code = PATCH;		}

	g_free ( mthd );

	return method_code;
}

// Constructs error message
void construct_error_message ( gchar* URI, int method, gchar* http_version, int status_code, GString* response[] ) {

	// Status line with error
	generate_status_line ( http_version, status_code, response );
	GString* body = g_string_new ( "" );
	if ( status_code != UNAUTHORIZED || g_str_has_prefix ( URI, "/secret" ) ) {
		GString* TMPbody = generate_error_content ( status_code );
		g_string_append ( body, TMPbody->str); g_string_free ( TMPbody, 1 );
	}
	int content_length = body->len;
	gchar* cont_len = g_strdup_printf( "%i\n", content_length);

	// Appropriate headers
	if ( status_code == UNAUTHORIZED && !g_str_has_prefix ( URI, "/secret" ) ) {
		g_string_append ( *response, "WWW-Authenticate: Basic realm=\"Restricted\"\n" );
	}
	g_string_append ( *response, "Content-Type: text/html; charset=UTF-8\n" );
	g_string_append ( *response, "Content-Length: " );
	g_string_append ( *response, cont_len );
	g_free ( cont_len );
	g_string_append ( *response, "Connection: close\n" );
	g_string_append ( *response, "\n" );

	// Feedback displayed
	if ( method != 2 ) { g_string_append ( *response, body->str ); }
	
	g_string_free ( body, 1 );
}

// Display error feedback in HTML 5 page
GString* generate_error_content ( int status_code ) {

	GString* body = g_string_new ( "" );

	g_string_append ( body, "<!DOCTYPE html>\n" );
	g_string_append (body, "<body>\n");

	if		( status_code == NOTIMPLEMENTED )	{ g_string_append ( body, "Error 501: Method not implemented by server\n" ); }
	else if		( status_code == BADREQUEST )		{ g_string_append ( body, "Error 400: Bad HTTP request recieved\n" ); }
	else if		( status_code == NOTFOUND )		{ g_string_append ( body, "Error 404: URL requested not found\n" ); }
	else if		( status_code == UNAUTHORIZED )		{ g_string_append ( body, "Error 401: User unauthorized for URL requested\n" ); }
	else							{ g_string_append ( body, "Error 500: An internal server error occurred\n" ); }

	g_string_append (body, "</body>\n");

	return body;
}






/****************************************************
 *	DICTIONARY STRUCTURE HELPER FUNCTIONS
 ****************************************************/


// Takes in tictionary structure to insert into "by reference", and a gchar key and value
// Key and value duplicated and initialized as a gchar pair (pair consists of key and value)
// Then inserted into next available slot in dictionary, increasing it's length
void dictionary_insert ( dictionary* dict, gchar* key, gchar* value ) {
	
	gchar* d_key = g_strdup ( key );
	gchar* d_value = g_strdup ( value );
	
	g_strchomp ( d_key ); g_strchomp ( d_value );

	gchar_pair to_insert = { d_key, d_value };

	(*dict).contents[(*dict).length] = to_insert;
	(*dict).length++;
}

// Takes in specified dictionary and searches it by key
// Returns gchar equivalent of value associated with key
// NULL if key is not found in dictionary
gchar* dictionary_search ( dictionary dict, gchar* key ) {

	for( int i = 0; i < dict.length; i++ ) {
		if( strcmp ( dict.contents[i].key, key ) == 0 ){
			return g_strdup ( dict.contents[i].value ) ;
		}
	}
	
	return NULL;
}

// Deallocates each gchar key-value pair in dicitonary
void dictionary_deallocate ( dictionary* dict ) {

	for( int i = 0; i < (*dict).length; i++ ) {

		g_free ( (*dict).contents[i].key );
		g_free ( (*dict).contents[i].value );
	}
}
