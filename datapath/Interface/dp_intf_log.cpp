#include <unistd.h>
#include "../dp_ctx.h"
#include "dp_intf.h"
#include "../../FireWall/acl/acldb.h"
#include "dp_intf_log.h"

void
tcp_dump_recv_logger(
              dp_ctx_t *dp_ctx,
              dp_intf_t *intf,
              pkt_block_t *pkt_block,
              gen_proto_id_t hdr_type){

    int rc = 0 ;
    acl_action_t acl_action;

    if (dp_ctx->log.all || 
        dp_ctx->log.recv ||
        intf->log_info.recv) {

        int sock_fd = ((dp_ctx->log.is_stdout || 
                        intf->log_info.is_stdout)) ? STDOUT_FILENO : -1;
        
        FILE *log_file1 = (dp_ctx->log.all || dp_ctx->log.recv) ?
                dp_ctx->log.log_file : NULL;
        FILE *log_file2 = (intf->log_info.recv || intf->log_info.all) ?
                intf->log_info.log_file : NULL;

        if (log_file1 && 
             dp_ctx->log.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (
                dp_ctx->log.acc_lst_filter->mtrie, pkt_block);

           if (acl_action == ACL_DENY) log_file1 = NULL;
        }

        if (log_file2 && 
             intf->log_info.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (
                intf->log_info.acc_lst_filter->mtrie, pkt_block);

           if (acl_action == ACL_DENY) log_file2 = NULL;
        }

        if(sock_fd == -1 && 
            !log_file1 && !log_file2){
            return;
        }
   
        rc = sprintf ((char *)dp_ctx->recv_log_buffer, 
                        "\n%s(%s) <-- \n", 
                        dp_ctx->ctx_name, intf->if_name);

        tcp_dump(sock_fd,          /*Write the log to the FD*/
                 log_file1,                /*Write the log to the node's log file*/
                 log_file2,                /*Write the log to the interface log file*/
                 pkt_block,                /*Pkt and Pkt size to be written in log file*/
                 hdr_type,                 /*Starting hdr type of the pkt*/
                 dp_ctx->recv_log_buffer,  /*Buffer into which the formatted output 
                                              is to be written*/
                 rc,                       /*write OFFset*/
                 TCP_PRINT_BUFFER_SIZE - rc);   /*Buffer Max Size*/
    }
}

void
tcp_dump_l3_fwding_logger(
            dp_ctx_t *dp_ctx,
            dp_vrf_t *vrf,
            unsigned char *oif_name, 
            unsigned char *gw_ip){

    int rc = 0;
    
    if(!dp_ctx->log.l3_fwd)
        return;

    int sock_fd = dp_ctx->log.is_stdout ? STDOUT_FILENO : -1 ;

    FILE *log_file1 = (dp_ctx->log.all || dp_ctx->log.l3_fwd) ?
             dp_ctx->log.log_file : NULL;
     
    if(sock_fd == -1 && !log_file1)
        return;

    dp_ctx->send_log_buffer[0] = '\0';
    
    rc = sprintf((char *)dp_ctx->send_log_buffer,
            "L3 Fwd : (%s)%s --> %s\n", 
            dp_ctx->ctx_name, oif_name, gw_ip);

    tcp_write_data(sock_fd, log_file1, NULL, 
        (char *)dp_ctx->send_log_buffer, rc);
}

void
tcp_dump_send_logger(dp_ctx_t *dp_ctx,
              dp_intf_t *intf,
              pkt_block_t *pkt_block,
              gen_proto_id_t hdr_type){

    int rc = 0;
    acl_action_t acl_action;

    if(dp_ctx->log.all || 
         dp_ctx->log.send ||
         intf->log_info.send){

        int sock_fd = ((dp_ctx->log.is_stdout || 
                        intf->log_info.is_stdout)) ? STDOUT_FILENO : -1;

        FILE *log_file1 = (dp_ctx->log.all || dp_ctx->log.send) ?
                dp_ctx->log.log_file : NULL;
        FILE *log_file2 = (intf->log_info.send || intf->log_info.all) ? 
                intf->log_info.log_file : NULL;

        if (log_file1 && 
             dp_ctx->log.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (
                dp_ctx->log.acc_lst_filter->mtrie, pkt_block);

           if (acl_action == ACL_DENY) log_file1 = NULL;
        }

        if (log_file2 && 
             intf->log_info.acc_lst_filter ) {

            acl_action = access_list_evaluate_pkt_block (
                intf->log_info.acc_lst_filter->mtrie, pkt_block);
                
           if (acl_action == ACL_DENY) log_file2 = NULL;
        }

        if(sock_fd == -1 && 
            !log_file1 && !log_file2){
            return;
        }

        dp_ctx->send_log_buffer[0] = '\0';
        
        rc = sprintf((char *)dp_ctx->send_log_buffer,
                "\n%s(%s) --> \n", 
                dp_ctx->ctx_name, intf->if_name);

        tcp_dump(sock_fd,                  /*Write the log to the FD*/
                 log_file1,                /*Write the log to the node's log file*/
                 log_file2,                /*Write the log to the interface log file*/
                 pkt_block,                /*Pkt and Pkt size to be written in log file*/
                 hdr_type,                 /*Starting hdr type of the pkt*/
                 dp_ctx->send_log_buffer,  /*Buffer into which the formatted output is to be written*/
                 rc,                       /*write OFFset*/
                 TCP_PRINT_BUFFER_SIZE - rc);   /*Buffer Max Size*/
    }
}
