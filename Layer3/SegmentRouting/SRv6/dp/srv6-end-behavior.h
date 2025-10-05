#ifndef  __SRV6_END_BEHAVIOR_H

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct ipv6_hdr_ ipv6_hdr_t;
typedef struct srh_hdr_ srh_hdr_t;
typedef struct v6nexthop_ v6nexthop_t;

void
srv6_shift_and_forward(node_t *node,
                                    pkt_block_t *pkt_block);

#define fn_template(fn_name)    \
    void fn_name (node_t *node __attribute__((unused)), pkt_block_t *pkt_block __attribute__((unused)), ipv6_hdr_t *ipv6_hdr __attribute__((unused)), srh_hdr_t *srh __attribute__((unused)), v6nexthop_t *nexthop __attribute__((unused)))

fn_template(srv6_END);

fn_template(srv6_END_w_PSP);

fn_template(srv6_END_w_USP);

fn_template(srv6_END_w_PSP_USP);

fn_template(srv6_END_X);

fn_template(srv6_END_X_w_PSP);

fn_template(srv6_END_X_w_USP);

fn_template(srv6_END_X_w_PSP_USP);

fn_template(srv6_END_T);

fn_template(srv6_END_T_w_PSP);

fn_template(srv6_END_T_w_USP);

fn_template(srv6_END_T_w_PSP_USP);

fn_template(srv6_END_B6_ENCAP);

fn_template(srv6_END_BM);

fn_template(srv6_END_DX6);

fn_template(srv6_END_DX4);

fn_template(srv6_END_DT6);

fn_template(srv6_END_DT4);

fn_template(srv6_END_DT46);

fn_template(srv6_END_DX2);

fn_template(srv6_END_DX2V);

fn_template(srv6_END_DT2U);

fn_template(srv6_END_DT2M);

fn_template(srv6_END_B6_ENCAPS_Red);

fn_template(srv6_END_w_USD);

fn_template(srv6_END_w_PSP_USD);

fn_template(srv6_END_X_USP_USD);

fn_template(srv6_END_w_PSP_USP_USD);

fn_template(srv6_END_X_w_USD);

fn_template(srv6_END_X_w_PSP_USD);

fn_template(srv6_END_X_w_USP_USD);

fn_template(srv6_END_X_w_PSP_USP_USD);

fn_template(srv6_END_T_w_USD);

fn_template(srv6_END_T_w_PSP_USD);

fn_template(srv6_END_T_w_USP_USD);

fn_template(srv6_END_T_w_PSP_USP_USD);


#endif // ! __SRV6_END_BEHAVIOR_H