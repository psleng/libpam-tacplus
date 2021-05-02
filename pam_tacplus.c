/* pam_tacplus.c - PAM interface for TACACS+ protocol.
 *
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * Copyright 2015, 2016, 2017, 2018 Cumulus Networks, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#include "pam_tacplus.h"
#include "support.h"

#include <stdlib.h>     /* malloc */
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>      /* gethostbyname */
#include <sys/socket.h> /* in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>     /* va_ */
#include <signal.h>
#include <string.h>     /* strdup */
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
# include <openssl/rand.h>
#else
# include "libtac/lib/magic.h"
#endif

/* address of server discovered by pam_sm_authenticate */
tacplus_server_t active_server;

extern char *__vrfname;

/* privilege level, used for mapping from tacacs userid to local
 * tacacs{0...15} user
 */
static unsigned priv_level;

/* accounting task identifier */
static short unsigned int task_id = 0;


/* Helper functions */
int _pam_send_account(pam_handle_t *pamh, int tac_fd, int type,
    const char *user, char *tty, char *r_addr, char *cmd) {
    char buf[64];
    struct tac_attrib *attr = NULL;
    int retval = -1;
    struct areply re;

    re.msg = NULL;
    snprintf(buf, sizeof buf, "%lu", (unsigned long)time(NULL));

    if (type == TAC_PLUS_ACCT_FLAG_START) {
        tac_add_attrib(&attr, "start_time", buf);
    } else if (type == TAC_PLUS_ACCT_FLAG_STOP) {
        tac_add_attrib(&attr, "stop_time", buf);
    }
    snprintf(buf, sizeof buf, "%hu", task_id);
    tac_add_attrib(&attr, "task_id", buf);
    tac_add_attrib(&attr, "service", tac_service);
    if(tac_protocol[0] != '\0')
      tac_add_attrib(&attr, "protocol", tac_protocol);
    if (cmd != NULL) {
        tac_add_attrib(&attr, "cmd", cmd);
    }

    retval = tac_acct_send(tac_fd, type, user, tty, r_addr, attr);

    /* attribute is no longer needed */
    tac_free_attrib(&attr);

    if(retval < 0) {
        pam_syslog(pamh, LOG_WARNING, "%s: send %s accounting failed"
            " (task %hu)", __func__, tac_acct_flag2str(type), task_id);
    }
    else if( tac_acct_read(tac_fd, &re) != TAC_PLUS_ACCT_STATUS_SUCCESS ) {
        pam_syslog(pamh, LOG_WARNING, "%s: accounting %s failed (task %hu)",
            __func__, tac_acct_flag2str(type), task_id);
        retval = -1;
    }
    else
        retval = 0;

    if(re.msg != NULL)
        free(re.msg);

    return retval;
}


/*
 * If all servers have been unresponsive, clear that state, so we try
 * them all.  It might have been transient.
 */
static void tac_chk_anyresp(void)
{
    int i, anyok=0;

    for(i = 0; i < tac_srv_no; i++) {
        if (!tac_srv[i].not_resp)
            anyok++;
    }
    if (!anyok) {
        for(i = 0; i < tac_srv_no; i++)
            tac_srv[i].not_resp = 0;
    }
}


/*
 * Send an accounting record to the TACACS+ server.
 * We send the start/stop accounting records even if the user is not known
 * to the TACACS+ server.   This seems non-intuitive, but it's the way
 * this code is written to work.
 */
int _pam_account(pam_handle_t *pamh, int argc, const char **argv,
    int type, char *cmd) {

    int retval;
    int ctrl;
    char *user = NULL;
    char *tty = NULL;
    char *r_addr = NULL;
    char *typemsg;
    int status = PAM_SESSION_ERR;
    int srv_i, tac_fd;

    typemsg = tac_acct_flag2str(type);
    ctrl = _pam_parse (pamh, argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: [%s] called (pam_tacplus"
            " v%u.%u.%u)", __func__, typemsg, PAM_TAC_VMAJ, PAM_TAC_VMIN,
            PAM_TAC_VPAT);

    _pam_get_user(pamh, &user);
    if (user == NULL)
        return PAM_USER_UNKNOWN;

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: username [%s] obtained", __func__,
            user);

    if (!task_id)
#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
        RAND_pseudo_bytes((unsigned char *) &task_id, sizeof(task_id));
#else
        task_id = (short unsigned int) tac_magic();
#endif

    _pam_get_terminal(pamh, &tty);
    if(!strncmp(tty, "/dev/", 5))
        tty += 5;
    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: tty [%s] obtained", __func__, tty);

    _pam_get_rhost(pamh, &r_addr);
    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: rhost [%s] obtained", __func__,
            r_addr);

    /* checks for specific data required by TACACS+, which should
       be supplied in command line  */
    if(tac_protocol[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "ACC: TACACS+ protocol type not configured");
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* when this module is called from within pppd or other
       application dealing with serial lines, it is likely
       that we will get hit with signal caused by modem hangup;
       this is important only for STOP packets, it's relatively
       rare that modem hangs up on accounting start */
    if(type == TAC_PLUS_ACCT_FLAG_STOP) {
        signal(SIGALRM, SIG_IGN);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
    }

    /*
     * If PAM_SESSION_ERR is used, then the pam config can't
     * ignore server failures, so use PAM_AUTHINFO_UNAVAIL.
     *
     * We have to make a new connection each time, because libtac is single
     * threaded (doesn't support multiple connects at the same time due to
     * use of globals)), and doesn't have support for persistent connections.
     * That's fixable, but not worth the effort at this point.
     *
     * TODO: this should be converted to use do_tac_connect eventually.
     */
    status = PAM_AUTHINFO_UNAVAIL;
    tac_chk_anyresp();
    for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        if (tac_srv[srv_i].not_resp)
            continue; /*  don't retry if previously not responding */
        tac_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
                                    tac_src_addr_info, __vrfname);
        if (tac_fd < 0) {
            pam_syslog(pamh, LOG_WARNING, "%s: error sending %s (fd)", __func__,
                typemsg);
            tac_srv[srv_i].not_resp = 1;
            continue;
        }
        if (ctrl & PAM_TAC_DEBUG)
            pam_syslog(pamh, LOG_DEBUG, "%s: connected with fd=%d"
                " to srv[%d] %s type=%s", __func__, tac_fd, srv_i,
                tac_srv[srv_i].addr ?  tac_ntop(tac_srv[srv_i].addr->ai_addr)
                  : "not set", typemsg);

        retval = _pam_send_account(pamh, tac_fd, type, user, tty, r_addr, cmd);
        close(tac_fd);
        if (retval < 0) {
            pam_syslog(pamh, LOG_WARNING, "%s: error sending %s (acct)",
                __func__, typemsg);
        } else {
            status = PAM_SUCCESS;
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "%s: [%s] for [%s] sent",
                    __func__, typemsg, user);
        }

        if ((status == PAM_SUCCESS) && !(ctrl & PAM_TAC_ACCT)) {
            /* do not send acct start/stop packets to _all_ servers */
            break;
        }
    }

    if (type == TAC_PLUS_ACCT_FLAG_STOP) {
        signal(SIGALRM, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
    }
    return status;
}


/*
 * Talk to the server for authentication
 */
static int tac_auth_converse(int ctrl, int fd, int *sptr,
    char *pass, pam_handle_t * pamh) {
    int msg;
    int ret = 1;
    struct areply re = { .attr = NULL, .msg = NULL, .status = 0, .flags = 0 };
    struct pam_message conv_msg = { .msg_style = 0, .msg = NULL };
    struct pam_response *resp = NULL;

    msg = tac_authen_read(fd, &re);

    if (NULL != re.msg) {
        conv_msg.msg = re.msg;
    }

    /* talk the protocol */
    switch (msg) {
        case TAC_PLUS_AUTHEN_STATUS_PASS:
            /* success */
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_PASS");
            if (NULL != conv_msg.msg) {
                int retval = -1;

                conv_msg.msg_style = PAM_TEXT_INFO;
                retval = converse(pamh, 1, &conv_msg, &resp);
                if (PAM_SUCCESS == retval) {
                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        pam_syslog(pamh, LOG_DEBUG, "send msg=\"%s\"",
                            conv_msg.msg);
                }
                else {
                    pam_syslog(pamh, LOG_WARNING, "%s: error sending"
                        " msg=\"%s\", retval=%d", __func__, conv_msg.msg,
                        retval);
                }
            }
            *sptr = PAM_SUCCESS;
            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_FAIL:
            /*
             * We've already validated that the user is known, so
             * this will be a password mismatch, or user not permitted
             * on this host, or at this time of day, etc.
             */
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_FAIL");
            if (NULL != conv_msg.msg) {
                int retval = -1;

                conv_msg.msg_style = PAM_ERROR_MSG;
                retval = converse(pamh, 1, &conv_msg, &resp);
                if (PAM_SUCCESS == retval) {
                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        pam_syslog(pamh, LOG_DEBUG, "send msg=\"%s\"",
                            conv_msg.msg);
                }
                else {
                    pam_syslog(pamh, LOG_WARNING, "%s: error sending msg="
                        "\"%s\", retval=%d", __func__, conv_msg.msg, retval);
                }
            }

            *sptr = PAM_AUTH_ERR;
            ret = 0;
            pam_syslog(pamh, LOG_NOTICE, "auth failed %d", msg);
            break;

        case TAC_PLUS_AUTHEN_STATUS_GETDATA:
            /* not implemented */
            if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_GETDATA");

            if (NULL != conv_msg.msg) {
                int retval = -1;
                int echo_off = (0x1 == (re.flags & 0x1));

                conv_msg.msg_style = echo_off ? PAM_PROMPT_ECHO_OFF :
                    PAM_PROMPT_ECHO_ON;
                retval = converse(pamh, 1, &conv_msg, &resp);
                if (PAM_SUCCESS == retval) {
                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        pam_syslog(pamh, LOG_DEBUG, "sent msg=\"%s\", resp="
                            "\"%s\"", conv_msg.msg, resp->resp);

                    if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
                        pam_syslog(pamh, LOG_DEBUG, "%s: calling"
                            " tac_cont_send", __func__);

                    if (0 > tac_cont_send_seq(fd, resp->resp, re.seq_no + 1)) {
                        pam_syslog(pamh, LOG_ERR, "error sending continue req"
                            " to TACACS+ server");
                        *sptr = PAM_AUTHINFO_UNAVAIL;
                    }
                }
                else {
                    pam_syslog(pamh, LOG_WARNING, "%s: error sending msg="
                        "\"%s\", retval=%d (%s)", __func__, conv_msg.msg,
                        retval, pam_strerror(pamh, retval));
                    *sptr = PAM_AUTHINFO_UNAVAIL;
                }
            }
            else {
                pam_syslog(pamh, LOG_ERR, "GETDATA response with no message,"
                    " returning PAM_AUTHINFO_UNAVAIL");

                *sptr = PAM_AUTHINFO_UNAVAIL;
            }

            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_GETUSER:
            /* not implemented */
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_GETUSER");

            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_GETPASS:
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_GETPASS");

            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "%s: tac_cont_send called",
                    __func__);

            if (tac_cont_send(fd, pass) < 0) {
                pam_syslog(pamh, LOG_ERR, "error sending continue req to"
                    " TACACS+ server");
                ret = 0;
                break;
            }
            /* continue the while loop; go read tac response */
            break;

        case TAC_PLUS_AUTHEN_STATUS_RESTART:
            /* try it again */
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_RESTART (not impl)");

            /*
             * not implemented
             * WdJ: I *think* you can just do tac_authen_send(user, pass) again
             *      but I'm not sure
             */
            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_ERROR:
            /* server has problems */
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_ERROR");

            ret = 0;
            break;

        case TAC_PLUS_AUTHEN_STATUS_FOLLOW:
            /* server tells to try a different server address */
            /* not implemented */
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status:"
                    " TAC_PLUS_AUTHEN_STATUS_FOLLOW");

            ret = 0;
            break;

        default:
            if (msg < 0) {
                /* connection error */
                ret = 0;
                if (ctrl & PAM_TAC_DEBUG)
                    pam_syslog(pamh, LOG_DEBUG, "error communicating with"
                        " tacacs server");
                break;
            }

            /* unknown response code */
            ret = 0;
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "tacacs status: unknown response"
                    " 0x%02x", msg);
    }

    if (NULL != resp) {
       free(resp->resp);
       free(resp);
    }

    if (NULL != re.msg);
        free(re.msg);

    return ret;
}

/*
 * Only acct and auth now; should handle all the cases here
 * Talk to the tacacs server for each type of transaction conversation
 */
static void talk_tac_server(int ctrl, int fd, char *user, char *pass,
                            char *tty, char *r_addr, struct tac_attrib **attr,
                            int *sptr, struct areply *reply,
                            pam_handle_t * pamh) {
    if (!pass) { /*  accounting */
        int retval;
        struct areply arep;
        if (attr)
            retval = tac_author_send(fd, user, tty, r_addr, *attr);
        if(!attr || retval < 0) {
            pam_syslog(pamh, LOG_ERR, "error getting authorization");
            *sptr =  PAM_AUTHINFO_UNAVAIL;
            return;
        }

        if (ctrl & PAM_TAC_DEBUG)
            pam_syslog(pamh, LOG_DEBUG, "%s: sent authorization request for"
                " [%s]", __func__, user);

        arep.msg = NULL;
        tac_author_read(fd, &arep);
        if (reply)
            *reply = arep;

        if(arep.status != AUTHOR_STATUS_PASS_ADD &&
            arep.status != AUTHOR_STATUS_PASS_REPL) {
            /*
             * if !pass, we are validating that the user is known, and
             * these status values usually means the server does not know
             * about the user so set USER_UNKNOWN, so we go on to the next
             * pam module.  This is consistent with libnss_tacplus.
             *
             * If pass, then this will usually be authorization denied due
             * to one of the permission checks.
             */
            if (!pass) {
                *sptr = PAM_USER_UNKNOWN;
                /*  do any logging at caller, since this is debug */
            }
            else {
                *sptr = PAM_PERM_DENIED;
                pam_syslog(pamh, LOG_WARNING, "TACACS+ authorization failed"
                           " for [%s] (tacacs status=%d)", user, arep.status);
            }
            if(arep.msg != NULL && !reply)
                free (arep.msg); /*  if reply is set, caller will free */
            return;
        }
        else  {
            *sptr = PAM_SUCCESS;
            if(arep.msg && !reply)
                free (arep.msg); /* caller will free if reply is set */
        }
    }
    else { /* authentication */
        if (tac_authen_send(fd, user, pass, tty, r_addr, TAC_PLUS_AUTHEN_LOGIN)
            < 0) {
            pam_syslog(pamh, LOG_ERR, "error sending auth req to TACACS+"
                " server");
        }
        else {
            while ( tac_auth_converse(ctrl, fd, sptr, pass, pamh))
                    ;
        }
    }
}


/*
 * find a responding tacacs server, and converse with it.
 * See comments at do_tac_connect() below
 */
static void find_tac_server(int ctrl, int *tacfd, char *user, char *pass,
                           char *tty, char *r_addr, struct tac_attrib **attr,
                           int *sptr, struct areply *reply,
                           pam_handle_t * pamh) {
    int fd = -1, srv_i;

    tac_chk_anyresp();
    for (srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        fd = -1;
        if (ctrl & PAM_TAC_DEBUG)
            pam_syslog(pamh, LOG_DEBUG, "%s: trying srv[%d] %s", __func__,
                srv_i, tac_srv[srv_i].addr ?
                tac_ntop(tac_srv[srv_i].addr->ai_addr) : "not set");

        /*
         * Try using our most recent server, if we had one.  This works for all
         * but accounting, where we should start from beginning of list.
         */
        if (active_server.addr) {
                fd = tac_connect_single(active_server.addr, active_server.key,
                                        tac_src_addr_info, __vrfname);
                if (fd < 0)
                    active_server.addr = NULL; /*  start from beginning */
        }
        if (fd < 0) {
            if (tac_srv[srv_i].not_resp)
                continue;
            /* no active_server, or it failed, and curr not failed */
            fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
                                    tac_src_addr_info, __vrfname);
        }
        if (fd < 0) {
            pam_syslog(pamh, LOG_ERR, "connection to srv[%d] %s failed: %m",
                srv_i, tac_srv[srv_i].addr ?
                tac_ntop(tac_srv[srv_i].addr->ai_addr) : "not set");
            active_server.addr = NULL;
            continue;
        }

        talk_tac_server(ctrl, fd, user, pass, tty, r_addr, attr, sptr,
            reply, pamh);

        if (*sptr == PAM_SUCCESS || *sptr == PAM_AUTH_ERR ||
            *sptr == PAM_USER_UNKNOWN) {
            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "%s: srv[%d] %s, pam_status=%d",
                    __func__, srv_i, tac_ntop(tac_srv[srv_i].addr->ai_addr),
                    *sptr);
            if (*sptr == PAM_SUCCESS) {
                if (active_server.addr == NULL) {
                    active_server.addr = tac_srv[srv_i].addr;
                    active_server.key = tac_srv[srv_i].key;
                }
                break;
            }
            /*  else try other servers, if any. On errs, won't need fd */
        }
        if (active_server.addr) {
            /*
             * We connected, but got a failure, don't re-use, start
             * over on next pass or connection attempt
             */
            active_server.addr = NULL;
        }
        close(fd);
        fd = -1;
    }
    *tacfd = fd;
}

/*
 * We have to make a new connection each time, because libtac is single
 * threaded (doesn't support multiple connects at the same time due to
 * use of globals), and doesn't have support for persistent connections.
 * That's fixable, but not worth the effort at this point.
 *
 * Trying to make this common code is ugly, but worth it to simplify
 * maintenance and debugging.
 *
 * The problem is that the definition allows for multiple tacacs
 * servers to be consulted, but a lot of the code was written such
 * that once a server is found that responds, it keeps using it.
 * That means when we are finding a server we need to do the full sequence.
 * The related issue is that the lower level code can't communicate
 * with multiple servers at the same time, and can't keep a connection
 * open.
 *
 * TODO: Really should have a structure to pass user, pass, tty, and r_addr
 * around everywhere.
 */
static int do_tac_connect(int ctrl, char *user, char *pass,
                          char *tty, char *r_addr, struct tac_attrib **attr,
                          struct areply *reply, pam_handle_t * pamh) {
    int status = PAM_AUTHINFO_UNAVAIL, fd;

    if (active_server.addr == NULL) { /* find a server with the info we want */
        find_tac_server(ctrl, &fd, user, pass, tty, r_addr, attr, &status,
            reply, pamh);
    }
    else { /* connect to the already chosen server, so we get
            * consistent results.  */
        if (ctrl & PAM_TAC_DEBUG)
            pam_syslog(pamh, LOG_DEBUG, "%s: use previous server %s", __func__,
               tac_ntop(active_server.addr->ai_addr));

        fd = tac_connect_single(active_server.addr, active_server.key,
                                tac_src_addr_info, __vrfname);
        if (fd < 0)
            pam_syslog(pamh, LOG_ERR, "reconnect failed to %s: %m",
                       tac_ntop(active_server.addr->ai_addr));
        else
            talk_tac_server(ctrl, fd, user, pass, tty, r_addr, attr, &status,
                reply, pamh);
    }

    /*
     * this is debug because we can get called for any user for
     * commands like sudo, not just tacacs users, so it's not an
     * error to fail here.  The caller can handle the logging.
     */
    if ((ctrl & PAM_TAC_DEBUG) && status != PAM_SUCCESS &&
        status != PAM_USER_UNKNOWN)
        pam_syslog(pamh, LOG_DEBUG, "no more servers to connect");
    if (fd != -1)
        close(fd); /* acct caller doesn't need connection */
    return status;
}

/* Main PAM functions */

/* authenticates user on remote TACACS+ server
 * returns PAM_SUCCESS if the supplied username and password
 * pair is valid
 * First check to see if the user is known to the server(s),
 * so we don't go through the password phase for unknown
 * users, and can return PAM_USER_UNKNOWN to the process.
 */
PAM_EXTERN
int pam_sm_authenticate (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {
    int ctrl, retval;
    char *user, *puser;
    char *pass;
    char *tty;
    char *r_addr;
    int status;
    struct tac_attrib **attr, *attr_s = NULL;

    priv_level = 0;
    user = pass = tty = r_addr = NULL;

    ctrl = _pam_parse(pamh, argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)",
            __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    /* reset static state in case we are re-entered */
    _reset_saved_user(pamh, ctrl & PAM_TAC_DEBUG);

    /*
     * If a mapped user entry already exists, we are probably being
     * used for su or sudo, so we need to get the original user password,
     * rather than the mapped user.
     * Decided based on auid != uid and then do the lookup, similar to
     * find_pw_user() in nss_tacplusc
     */
    _pam_get_user(pamh, &puser);
    user = get_user_to_auth(puser);
    if (user == NULL)
        return PAM_USER_UNKNOWN;
    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: user [%s] obtained", __func__, user);

    _pam_get_terminal(pamh, &tty);
    if (!strncmp(tty, "/dev/", 5))
        tty += 5;
    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: tty [%s] obtained", __func__, tty);

    _pam_get_rhost(pamh, &r_addr);
    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: rhost [%s] obtained", __func__,
            r_addr);

    /*
     * Since these attributes are just for validating that the user is known to
     * at least one server, it doesn't really matter whether these are "correct"
     */
    attr = &attr_s;
    tac_add_attrib(attr, "service", tac_service?tac_service:"shell");
    tac_add_attrib(attr, "protocol", tac_protocol?tac_protocol:"ssh");
    tac_add_attrib(attr, "cmd", "");

    status = do_tac_connect(ctrl, user, NULL, tty, r_addr, &attr_s, NULL, pamh);
    tac_free_attrib(&attr_s);
    if (status != PAM_SUCCESS) {
        if (ctrl & PAM_TAC_DEBUG)
            pam_syslog(pamh, LOG_DEBUG, "TACACS+ user [%s] unknown,"
                       " (pam status=%d)", user, status);
        goto err;
    }

    retval = tacacs_get_password (pamh, flags, ctrl, &pass);
    if (retval != PAM_SUCCESS || pass == NULL || *pass == '\0') {
        pam_syslog(pamh, LOG_ERR, "unable to obtain password");
        status = PAM_CRED_INSUFFICIENT;
        goto err;
    }

    retval = pam_set_item (pamh, PAM_AUTHTOK, pass);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "unable to set password");
        status = PAM_CRED_INSUFFICIENT;
        goto err;
    }

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: password obtained", __func__);

    status = do_tac_connect(ctrl, user, pass, tty, r_addr, NULL, NULL, pamh);

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: exit with pam status: %d", __func__,
            status);

err:
    if (user && user != puser)
        free(user); /* it was stdrup'ed */
    if (NULL != pass) {
        bzero(pass, strlen (pass));
        free(pass);
    }

    return status;
}    /* pam_sm_authenticate */


/* no-op function to satisfy PAM authentication module */
PAM_EXTERN
int pam_sm_setcred (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    int ctrl = _pam_parse (pamh, argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)",
            __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    return PAM_SUCCESS;
}    /* pam_sm_setcred */


/* authorizes user on remote TACACS+ server, i.e. checks
 * his permission to access requested service
 * returns PAM_SUCCESS if the service is allowed
 */
PAM_EXTERN
int pam_sm_acct_mgmt (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    int ctrl, status=PAM_AUTH_ERR;
    char *user;
    char *tty;
    char *r_addr;
    struct areply arep;
    struct tac_attrib *attr_s = NULL, *attr;

    user = tty = r_addr = NULL;
    memset(&arep, 0, sizeof(arep));

    /* this also obtains service name for authorization
       this should be normally performed by pam_get_item(PAM_SERVICE)
       but since PAM service names are incompatible TACACS+
       we have to pass it via command line argument until a better
       solution is found ;) */
    ctrl = _pam_parse (pamh, argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)",
            __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    _pam_get_user(pamh, &user);
    if (user == NULL)
        return PAM_USER_UNKNOWN;


    _pam_get_terminal(pamh, &tty);
    if(!strncmp(tty, "/dev/", 5))
        tty += 5;

    _pam_get_rhost(pamh, &r_addr);

    /* checks for specific data required by TACACS+, which should
       be supplied in pam module command line  */
    if(!*tac_service) {
        pam_syslog(pamh, LOG_ERR, "TACACS+ service type not configured");
        return PAM_AUTHINFO_UNAVAIL;
    }
    tac_add_attrib(&attr_s, "service", tac_service);

    if(tac_protocol != NULL && tac_protocol[0] != '\0')
          tac_add_attrib(&attr_s, "protocol", tac_protocol);
    else
          pam_syslog(pamh, LOG_ERR, "TACACS+ protocol type not configured"
              " (IGNORED)");

    tac_add_attrib(&attr_s, "cmd", "");

    memset(&arep, 0, sizeof arep);

    /*
     * Check if user is authorized, independently of authentication.
     * Authentication may have happened via ssh public key, rather than
     * via TACACS+.  PAM should not normally get to this entry point if
     * user is not yet authenticated.
     * We only write the mapping entry (if needed) when authorization
     * is succesful.
     * attr is not used here, but having a non-NULL value is how
     * talk_tac_server() distinguishes that it is an acct call, vs auth
     * TODO: use a different mechanism
    */
    status = do_tac_connect(ctrl, user, NULL, tty, r_addr, &attr_s,
        &arep, pamh);
    tac_free_attrib(&attr_s);
    if(active_server.addr == NULL) {
        /* we need to return PAM_AUTHINFO_UNAVAIL here, rather than
         * PAM_AUTH_ERR, or we can't use "ignore" or auth_err=bad in the
         * pam configuration
         */
        status = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    if(status) {
        if (ctrl & PAM_TAC_DEBUG)
            pam_syslog(pamh, LOG_NOTICE, "No TACACS mapping for %s after auth"
                " failure", user);
        goto cleanup;
    }

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: user [%s] successfully authorized",
            __func__, user);

    attr = arep.attr;
    while (attr != NULL)  {
        const int new_len = attr->attr_len+1; /* 1 longer for terminating 0 */
        char attribute[new_len];
        char value[new_len];
        char attrenv[new_len];
        char tmpstr[new_len];
        char *sep;

        snprintf(tmpstr, sizeof tmpstr, "%*s", attr->attr_len,attr->attr);
        sep = index(tmpstr, '=');
        if(sep == NULL)
            sep = index(tmpstr, '*');
        if(sep != NULL) {
            *sep = '\0';
            snprintf(attribute, sizeof attribute, "%s", tmpstr);
            snprintf(value, sizeof value, "%s", ++sep);

            size_t i;
            for (i = 0; attribute[i] != '\0'; i++) {
                attribute[i] = toupper(attribute[i]);
                if (attribute[i] == '-')
                    attribute[i] = '_';
            }

            if (ctrl & PAM_TAC_DEBUG)
                pam_syslog(pamh, LOG_DEBUG, "%s: returned attribute `%s(%s)'"
                    " from server", __func__, attribute, value);

            if(strncmp(attribute, "PRIV", 4) == 0) {
                char *ok;

                priv_level = (unsigned)strtoul(value, &ok, 0);
                /* if this fails, we leave priv_level at 0, which is
                 * least privileged, so that's OK, but at least report it
                 */
                if (ok == value)
                    pam_syslog(pamh, LOG_WARNING,
                        "%s: non-numeric privilege for %s, got (%s)",
                        __func__, attribute, value);
            }

            /*
             * make returned attributes available for other PAM modules via PAM
             * environment. Since separator can be = or *, ensure it's = for
             * the env.
             */
            snprintf(attrenv, sizeof attrenv, "%s=%s", attribute, value);
            if (pam_putenv(pamh, attrenv) != PAM_SUCCESS)
                pam_syslog(pamh, LOG_WARNING, "%s: unable to set PAM"
                    " environment (%s)", __func__, attribute);

        } else {
            pam_syslog(pamh, LOG_WARNING, "%s: invalid attribute `%s',"
                " no separator", __func__, attr->attr);
        }
        attr = attr->next;
    }

    update_mapped(pamh, user, priv_level, r_addr);


cleanup:
    /* free returned attributes */
    if(arep.attr != NULL)
        tac_free_attrib(&arep.attr);

    if(arep.msg != NULL)
        free (arep.msg);

    return status;
}    /* pam_sm_acct_mgmt */

/*
 * accounting packets may be directed to any TACACS+ server,
 * independent from those used for authentication and authorization;
 * they may be also directed to all specified servers
 */

static short unsigned int session_taskid;

/*
 * send START accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 * sets sess_taskid so it can be used in close_session, so that
 * accounting start and stop records have the same task_id, as
 * the specification requires.
 */
PAM_EXTERN
int pam_sm_open_session (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    if (!task_id)
#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
        RAND_pseudo_bytes((unsigned char *) &task_id, sizeof(task_id));
#else
        task_id=(short int) tac_magic();
#endif
    session_taskid = task_id;
    return _pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_START, NULL);
}    /* pam_sm_open_session */

/* sends STOP accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
PAM_EXTERN
int pam_sm_close_session (pam_handle_t * pamh, int flags,
    int argc, const char **argv) {
    int rc;
    char *user;

    _pam_get_user(pamh, &user);

    task_id = session_taskid; /* task_id must match start */
    rc = _pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_STOP, NULL);
    __update_loguid(user); /* now dead, cleanup mapping */
    return rc;
}    /* pam_sm_close_session */


#ifdef PAM_SM_PASSWORD
/* Tested for servers that require password change during challenge/response */
PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
    int argc, const char **argv) {

    int ctrl;
    char *user;
    char *pass;
    char *tty;
    char *r_addr;
    const void *pam_pass = NULL;
    int status;

    user = pass = tty = r_addr = NULL;

    ctrl = _pam_parse(pamh, argc, argv);

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)"
            " (flags=%d, argc=%d)", __func__, PAM_TAC_VMAJ, PAM_TAC_VMIN,
            PAM_TAC_VPAT, flags, argc);

    if (   (pam_get_item(pamh, PAM_OLDAUTHTOK, &pam_pass) == PAM_SUCCESS)
        && (pam_pass != NULL) ) {
         if ((pass = strdup(pam_pass)) == NULL)
              return PAM_BUF_ERR;
    } else {
        pass = strdup("");
    }

    _pam_get_user(pamh, &user);
    if (user == NULL) {
        if(pass) {
                free(pass);
        }
        return PAM_USER_UNKNOWN;
    }

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: user [%s] obtained", __func__, user);

    _pam_get_terminal(pamh, &tty);
    if (tty && !strncmp(tty, "/dev/", 5))
        tty += 5;
    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: tty [%s] obtained", __func__,
            tty?tty:"UNKNOWN");

    _pam_get_rhost(pamh, &r_addr);
    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: rhost [%s] obtained", __func__,
            r_addr?r_addr:"UNKNOWN");

    if (PAM_SILENT != (flags & PAM_SILENT))
        status = do_tac_connect(ctrl, user, pass, tty, r_addr, NULL, NULL,
                                pamh);
    else
        status = PAM_AUTHTOK_ERR;

    if (status != PAM_SUCCESS && status != PAM_AUTHTOK_ERR)
        pam_syslog(pamh, LOG_ERR, "no more servers to connect");

    if (ctrl & PAM_TAC_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "%s: exit with pam status: %d", __func__,
            status);

    if (NULL != pass) {
        bzero(pass, strlen(pass));
        free(pass);
        pass = NULL;
    }

    return status;

}    /* pam_sm_chauthtok */
#endif


#ifdef PAM_STATIC
struct pam_module _pam_tacplus_modstruct {
    "pam_tacplus",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
#ifdef PAM_SM_PASSWORD
    pam_sm_chauthtok
#else
    NULL
#endif
};
#endif
