#ifndef CLAWSEC_EXEC_H
#define CLAWSEC_EXEC_H

#ifdef GAPING_SECURITY_HOLE
/* Run program with encrypted I/O over sockfd. Does not return on success. */
void run_encrypted_exec(int sockfd, const char *prog);
#endif

#endif
